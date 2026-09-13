"""
BOLA Detector — Broken Object Level Authorization
=================================================
OWASP API1:2023 — Ən geniş yayılmış API zəifliyi.

Bu detektor köhnə "ID dəyişdir, 200-ü gözlə" yanaşmasından fərqlidir:
  1. Ownership graph-dan real cross-ownership hədəfləri götürür
  2. Actor × Resource × Action matrisini qurur
  3. EvidenceEngine ilə confidence hesablayır
  4. Yalnız real authorization violation sübut olunanda flag qoyur

Əhatə:
  - Horizontal IDOR (Read/Write/Delete)
  - BOLA — object-level authorization yoxluğu
  - Bulk authorization (GET /users/all)
  - BOPLA — property-level ifşa
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

from rich.console import Console

from core.model import (
    Actor, Resource, ActionType, ExpectedPolicy,
    AuthorizationTest, VulnClass,
)
from core.ownership import OwnershipGraph, OwnedObject
from analysis.evidence import EvidenceEngine
from modules.http_client import AsyncClient, ScanConfig

console = Console()

_EVIDENCE = EvidenceEngine()

# HTTP method → ActionType
_METHOD_ACTION = {
    "GET":    ActionType.READ,
    "HEAD":   ActionType.READ,
    "POST":   ActionType.WRITE,
    "PUT":    ActionType.WRITE,
    "PATCH":  ActionType.WRITE,
    "DELETE": ActionType.DELETE,
}

# ── Kandidat ID-lər ───────────────────────────────────────────────────────────
import uuid

def _id_candidates(obj_id: str, kind: str = "numeric") -> list[str]:
    if kind == "uuid":
        return [str(uuid.uuid4()) for _ in range(4)] + \
               ["00000000-0000-0000-0000-000000000000"]
    try:
        base = int(obj_id)
        adj  = [str(base + i) for i in range(-5, 6) if base + i > 0 and str(base + i) != obj_id]
        fixed = ["1", "2", "3", "100", "9999"]
        return list(dict.fromkeys(fixed + adj))[:15]
    except ValueError:
        return ["1", "2", "admin", "root", obj_id + "1"]


# ── Əsas detektor ─────────────────────────────────────────────────────────────

async def detect_bola(
    url: str,
    client: AsyncClient,
    cfg: ScanConfig,
    actor_low:  Actor,
    actor_high: Actor,
    graph: OwnershipGraph,
) -> list[dict]:

    results = []
    lock    = asyncio.Lock()
    fp      = {}  # local dedup: url+method → seen

    parsed = urlparse(url)
    path   = parsed.path

    # Baseline — actor_low ilə
    base_hdrs = cfg.build_headers(cfg.low_token)
    baseline  = await client.get(url, base_hdrs, allow_redirects=True)
    bl_status = baseline.status if baseline else 0
    bl_body   = baseline.body   if baseline else ""

    console.print(
        f"[cyan][*] BOLA baseline: HTTP {bl_status} "
        f"({len(bl_body.encode())}B)[/cyan]"
    )

    # Baseline resource-u zənginləşdir
    base_resource = Resource.from_url(url)
    if baseline and baseline.body:
        base_resource.extract_from_response(baseline.body)

    async def run_test(test_url: str, method: str, actor: Actor,
                        resource: Resource, expected: ExpectedPolicy,
                        hdrs: dict, body_payload: dict = None):
        key = f"{method}:{test_url}"
        if key in fp:
            return
        fp[key] = True

        resp = await client.request(method, test_url, hdrs,
                                    body=body_payload, allow_redirects=True)
        if not resp:
            return

        if cfg.verbose:
            console.print(
                f"  [dim]{method} {test_url}: {resp.status}[/dim]"
            )

        # Resource-u cavabla zənginləşdir
        resource.extract_from_response(resp.body)

        test = AuthorizationTest(
            actor=actor, resource=resource,
            action=_METHOD_ACTION.get(method, ActionType.READ),
            method=method, expected_policy=expected,
            observed_status=resp.status,
            observed_body=resp.body,
            observed_headers=resp.headers,
            elapsed=resp.elapsed,
        )

        result = _EVIDENCE.evaluate(test, bl_body, bl_status)
        if result.is_finding:
            finding = result.to_finding()
            console.print(
                f"  [bold red][!] BOLA [{result.confidence}%] "
                f"{method} {test_url}[/bold red]"
            )
            async with lock:
                results.append(finding)

    tasks = []

    # ── 1. Ownership-əsaslı cross-access testlər ─────────────────────────────
    cross_targets = graph.get_cross_targets(actor_low.identity)
    if cross_targets:
        console.print(
            f"[cyan][*] BOLA: ownership graph — "
            f"{len(cross_targets)} cross-ownership hədəf[/cyan]"
        )
        for obj in cross_targets[:20]:
            r = Resource(
                url=obj.url, object_type=obj.object_type,
                object_id=obj.object_id, owner_id=obj.owner_id,
                tenant_id=obj.tenant_id,
            )
            low_hdrs = cfg.build_headers(cfg.low_token)
            for method in ["GET", "PUT", "DELETE", "PATCH"]:
                payload = {"data": "test"} if method in {"PUT","PATCH"} else None
                tasks.append(run_test(
                    obj.url, method, actor_low, r,
                    ExpectedPolicy.DENY, low_hdrs, payload
                ))

    # ── 2. ID mutation testlər (ownership graph yoxdursa) ─────────────────────
    id_match = re.search(
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|'
        r'\d{1,15})(?:/|$)', path
    )
    if id_match:
        orig_id  = id_match.group(1)
        id_kind  = "uuid" if "-" in orig_id else "numeric"
        cands    = _id_candidates(orig_id, id_kind)

        console.print(
            f"[cyan][*] BOLA: ID mutation — "
            f"{len(cands)} kandidat × 3 method[/cyan]"
        )

        for cand in cands:
            new_path = path.replace(orig_id, cand, 1)
            test_url = urlunparse(parsed._replace(path=new_path))

            r = Resource.from_url(test_url)
            r.owner_id  = base_resource.owner_id
            r.tenant_id = base_resource.tenant_id

            low_hdrs = cfg.build_headers(cfg.low_token)
            for method in ["GET", "PUT", "DELETE"]:
                expected = (ExpectedPolicy.DENY
                            if base_resource.owner_id
                            else ExpectedPolicy.UNKNOWN)
                payload = {"data": "test"} if method == "PUT" else None
                tasks.append(run_test(
                    test_url, method, actor_low, r,
                    expected, low_hdrs, payload
                ))

    # ── 3. Bulk authorization (GET /users = hamını görür?) ───────────────────
    # List endpoint-i yoxla — filtrsiz həddindən çox object qaytarırsa BOLA
    parsed2 = urlparse(url)
    list_path = re.sub(r'/\d+.*$', '', parsed2.path)
    list_path = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*$',
        '', list_path
    )
    if list_path and list_path != parsed2.path:
        list_url = urlunparse(parsed2._replace(path=list_path))
        r = Resource.from_url(list_url)
        r.object_type = "bulk_list"
        tasks.append(run_test(
            list_url, "GET", actor_low, r,
            ExpectedPolicy.UNKNOWN, cfg.build_headers(cfg.low_token)
        ))
        # ?limit=9999 trick
        tasks.append(run_test(
            list_url + "?limit=9999&page=1", "GET", actor_low, r,
            ExpectedPolicy.UNKNOWN, cfg.build_headers(cfg.low_token)
        ))

    # ── 4. BOPLA — Property-level authorization ───────────────────────────────
    # Cavabda admin/internal property-lər görünürmü?
    if baseline and baseline.body:
        import json as _j
        try:
            data = _j.loads(baseline.body)
            priv_fields = {"role", "is_admin", "permissions", "internal_notes",
                           "salary", "ssn", "private_key", "api_key", "secret"}
            found_priv = []
            def _check(obj):
                if isinstance(obj, dict):
                    for k in obj:
                        if k.lower() in priv_fields:
                            found_priv.append(k)
                        _check(obj[k])
                elif isinstance(obj, list):
                    for item in obj[:5]:
                        _check(item)
            _check(data)
            if found_priv:
                console.print(
                    f"[bold yellow][!] BOPLA: həssas property-lər açıq: "
                    f"{found_priv}[/bold yellow]"
                )
                async with lock:
                    results.append({
                        "type":       VulnClass.BOPLA.value,
                        "severity":   "HIGH",
                        "confidence": 75,
                        "url":        url,
                        "method":     "GET",
                        "status":     baseline.status,
                        "reason": (
                            f"Cavabda imtiyazlı property-lər ifşa olundu: {found_priv}. "
                            "Bu property-lər yalnız admin/owner üçün görünməlidir."
                        ),
                        "evidence": {"exposed_properties": found_priv},
                        "snippet":  baseline.body[:500],
                    })
        except Exception:
            pass

    await asyncio.gather(*tasks)
    return results
