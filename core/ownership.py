"""
Ownership Graph — Kim hansı resursa sahibdir?

Tool öz-özünə öyrənir:
  Actor A → [object_101, object_201, ...]
  Actor B → [object_102, object_202, ...]

Sonra:
  A → object_102  →  Expected: DENY  (cross-ownership test)
  B → object_101  →  Expected: DENY

Bu, testin "kor" ID dəyişikliyindən fərqidir —
real ownership-əsaslı differential test edilir.
"""

from __future__ import annotations
import asyncio
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

console = Console()


@dataclass
class OwnedObject:
    object_id:   str
    object_type: str
    url:         str
    owner_id:    str
    tenant_id:   str = ""
    raw_body:    str = ""


class OwnershipGraph:
    """
    İki actor arasında ownership xəritəsi.
    Discovery zamanı doldurulur, test zamanı istifadə edilir.
    """

    def __init__(self):
        # actor_identity → list[OwnedObject]
        self._graph: dict[str, list[OwnedObject]] = defaultdict(list)

    def add(self, actor_id: str, obj: OwnedObject):
        # Eyni object-i iki dəfə əlavə etmə
        existing = {o.object_id for o in self._graph[actor_id]}
        if obj.object_id not in existing:
            self._graph[actor_id].append(obj)

    def get_objects(self, actor_id: str) -> list[OwnedObject]:
        return self._graph.get(actor_id, [])

    def get_cross_targets(self, actor_id: str) -> list[OwnedObject]:
        """actor_id-in SAHİBİ OLMADAĞI obyektlər — test üçün hədəflər."""
        own = {o.object_id for o in self._graph.get(actor_id, [])}
        targets = []
        for other_id, objects in self._graph.items():
            if other_id == actor_id:
                continue
            for obj in objects:
                if obj.object_id not in own:
                    targets.append(obj)
        return targets

    def summary(self) -> str:
        lines = []
        for actor, objects in self._graph.items():
            lines.append(f"  {actor}: {len(objects)} object(s)")
        return "\n".join(lines) if lines else "  (boş)"


# ── Ownership discovery ───────────────────────────────────────────────────────

_OWNER_FIELDS = re.compile(
    r'^(owner_id|user_id|creator_id|created_by|author_id|member_id|account_id)$',
    re.IGNORECASE,
)
_TENANT_FIELDS = re.compile(
    r'^(tenant_id|org_id|organization_id|workspace_id|company_id|team_id)$',
    re.IGNORECASE,
)
_ID_FIELDS = re.compile(
    r'^(id|object_id|resource_id|uuid)$', re.IGNORECASE,
)

_LIST_PATHS = re.compile(
    r'/(users|orders|invoices|reports|files|documents|projects|'
    r'tickets|messages|accounts|members|items|products|subscriptions)/?$',
    re.IGNORECASE,
)


def _extract_ids_from_body(body: str, base_url: str) -> list[str]:
    """List cavabından object URL-lərini çıxar."""
    try:
        data = json.loads(body)
        ids = []

        def _collect(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if _ID_FIELDS.match(k) and v:
                        ids.append(str(v))
                    elif isinstance(v, (dict, list)):
                        _collect(v)
            elif isinstance(obj, list):
                for item in obj[:20]:  # max 20 object
                    _collect(item)

        _collect(data)
        return list(dict.fromkeys(ids))[:15]
    except Exception:
        return []


def _extract_ownership(body: str) -> tuple[str, str]:
    """Cavab body-sindən owner_id və tenant_id çıxar."""
    try:
        data = json.loads(body)

        def _flat(obj, result=None):
            if result is None:
                result = {}
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if not isinstance(v, (dict, list)):
                        result[k] = str(v)
                    else:
                        _flat(v, result)
            elif isinstance(obj, list) and obj:
                _flat(obj[0], result)
            return result

        flat = _flat(data)
        owner  = next((v for k, v in flat.items() if _OWNER_FIELDS.match(k)), "")
        tenant = next((v for k, v in flat.items() if _TENANT_FIELDS.match(k)), "")
        return owner, tenant
    except Exception:
        return "", ""


async def discover_ownership(
    base_url: str,
    actor_low_id:  str,
    actor_high_id: str,
    low_hdrs:  dict,
    high_hdrs: dict,
    client,
    verbose: bool = False,
) -> OwnershipGraph:
    """
    Hər iki actor üçün ownership graph qur.
    List endpoint-ləri yoxla → object ID-lərini topla → hər ID üçün
    GET ilə owner məlumatını təsdiqlə.
    """
    graph = OwnershipGraph()
    from urllib.parse import urlparse, urljoin
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    path   = parsed.path

    # List endpoint aşkarla
    list_candidates = []
    if _LIST_PATHS.search(path):
        list_candidates.append(base_url)

    # Path-dan list endpoint törət
    parts = [p for p in path.split("/") if p]
    for i in range(len(parts), 0, -1):
        candidate = base + "/" + "/".join(parts[:i])
        if _LIST_PATHS.search(candidate):
            list_candidates.append(candidate)
            break

    if not list_candidates:
        # Ümumi list endpoint-lər
        for ep in ["/api/v1/users/me", "/api/me", "/profile",
                   "/api/v1/orders", "/api/v1/invoices"]:
            list_candidates.append(urljoin(base + "/", ep.lstrip("/")))

    console.print(f"[cyan][*] Ownership discovery: {len(list_candidates)} list endpoint...[/cyan]")

    for list_url in list_candidates[:5]:
        for actor_id, hdrs in [(actor_low_id, low_hdrs), (actor_high_id, high_hdrs)]:
            if not actor_id or not hdrs:
                continue
            resp = await client.get(list_url, hdrs, allow_redirects=True)
            if not resp or resp.status not in {200, 201}:
                continue

            ids = _extract_ids_from_body(resp.body, list_url)
            if verbose:
                console.print(f"  [dim]{actor_id}: {list_url} → {resp.status} | {len(ids)} ID[/dim]")

            # Hər ID üçün individual GET
            for obj_id in ids[:10]:
                obj_url = urljoin(list_url.rstrip("/") + "/", obj_id)
                detail = await client.get(obj_url, hdrs, allow_redirects=True)
                if not detail or detail.status != 200:
                    continue

                owner, tenant = _extract_ownership(detail.body)
                obj_type = path.split("/")[-1].rstrip("s") if path else "object"

                graph.add(actor_id, OwnedObject(
                    object_id   = obj_id,
                    object_type = obj_type,
                    url         = obj_url,
                    owner_id    = owner or actor_id,
                    tenant_id   = tenant,
                    raw_body    = detail.body[:300],
                ))

    total = sum(len(v) for v in graph._graph.values())
    console.print(f"[cyan][*] Ownership graph:\n{graph.summary()}[/cyan]")
    console.print(f"[cyan][*] Ümumi: {total} object[/cyan]")
    return graph
