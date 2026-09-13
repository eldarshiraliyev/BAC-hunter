"""
Access Control Module — Universal BAC Scanner
=============================================
Əhatə etdiyi kateqoriyalar:
  - Horizontal IDOR/BOLA (eyni rol, başqa resurs)
  - Vertical privilege escalation (aşağı rol → yuxarı funksiya)
  - Improper Access Control (ACL yoxlaması atlanır)
  - Cross-tenant access (multi-tenant ayrılığı)
  - Unauthorized modification (PUT/PATCH)
  - Unauthorized deletion (DELETE)
  - Read-only IDOR
  - Write/Update IDOR
  - Delete IDOR
  - Role/permission bypass
  - API authorization flaws
  - Method-level authorization

Real nümunələr:
  - Twitter: DM başqa hesabdan göndər (Horizontal IDOR, $1,080)
  - GitLab: başqa org-un CI/CD pipeline-ına toxic data inject et (Cross-tenant)
  - Uber: surücü hesabı ilə sıradan user-in məlumatını sil (Vertical + Delete IDOR)
  - HackerOne: read-only token ilə report-u dəyişdir (Role bypass)
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

from rich.console import Console

from config import SUCCESS_CODES, FORBIDDEN_CODES, HTTP_METHODS
from modules.http_client import AsyncClient, ScanConfig
from modules.validator import ResponseValidator, Deduplicator

console = Console()

# ── Sabitlər ──────────────────────────────────────────────────────────────────

# Role bypass üçün test header-ları
_ROLE_HEADERS = {
    "X-User-Role":        ["admin", "administrator", "superuser", "root", "staff", "moderator"],
    "X-Role":             ["admin", "administrator", "superuser"],
    "X-Auth-Role":        ["admin", "superuser"],
    "X-Permission":       ["admin", "write", "delete", "*"],
    "X-Access-Level":     ["admin", "9999", "100"],
    "X-Admin":            ["true", "1", "yes"],
    "X-Is-Admin":         ["true", "1"],
    "X-Superuser":        ["true", "1"],
    "X-Internal":         ["true", "1"],
    "X-Staff":            ["true", "1"],
    "X-Privileged":       ["true", "1"],
    "X-Bypass-Auth":      ["true", "1"],
    "X-Override-Auth":    ["true", "1"],
    "X-Auth-Override":    ["true"],
    "X-Debug":            ["true", "1"],
    # Bəzi framework-lər bu header-lara güvənir (Laravel, Django)
    "X-Auth-User-Id":     ["1", "0"],
    "X-User-Id":          ["1", "0"],
    "X-Authenticated-User": ["admin"],
}

# API authorization flaws — endpoint-lərdə metod-səviyyəli yoxlama
_API_AUTH_PATHS = [
    # REST CRUD endpoint-ləri — GET yoxlansada PUT/DELETE yoxlanılmır
    ("users",          ["GET", "POST", "PUT", "DELETE", "PATCH"]),
    ("user/1",         ["GET", "PUT", "DELETE", "PATCH"]),
    ("api/v1/users",   ["GET", "POST", "PUT", "DELETE"]),
    ("api/v2/users",   ["GET", "POST", "DELETE"]),
    ("accounts",       ["GET", "POST", "DELETE"]),
    ("account/1",      ["GET", "PUT", "DELETE"]),
    ("orders",         ["GET", "POST", "DELETE"]),
    ("order/1",        ["GET", "PUT", "DELETE", "PATCH"]),
    ("payments",       ["GET", "POST"]),
    ("payment/1",      ["GET", "DELETE", "REFUND"]),
    ("admin/users",    ["GET", "POST", "DELETE"]),
    ("reports",        ["GET", "POST", "DELETE"]),
    ("report/1",       ["GET", "PUT", "DELETE"]),
    ("files",          ["GET", "POST", "DELETE"]),
    ("file/1",         ["GET", "DELETE"]),
    ("messages",       ["GET", "POST", "DELETE"]),
    ("settings",       ["GET", "PUT", "POST"]),
    ("api/v1/admin",   ["GET", "POST", "DELETE"]),
]

# Cross-tenant test payload-ları
_TENANT_FIELDS = [
    "org_id", "organization_id", "tenant_id", "workspace_id",
    "company_id", "team_id", "shop_id", "store_id",
    "account_id", "business_id", "client_id", "group_id",
]

# BOLA test payloads — obyekt ID-ləri üçün
_BOLA_IDS = ["1", "2", "3", "0", "100", "9999",
             "00000000-0000-0000-0000-000000000000",
             "admin", "root", "superuser"]


# ── Universal probe ────────────────────────────────────────────────────────────

async def _probe(
    url: str, hdrs: dict, method: str,
    label: str, reason: str, vtype: str,
    client: AsyncClient, cfg: ScanConfig,
    validator: ResponseValidator,
    results: list, lock: asyncio.Lock,
    dedup: Deduplicator,
    body: dict = None,
    expected_fail: bool = True,
):
    resp = await client.request(method, url, hdrs, body=body, allow_redirects=True)
    if not resp:
        return

    if cfg.verbose:
        console.print(f"  [dim][{vtype}] {method} {url}: {resp.status}[/dim]")

    vr = validator.validate(resp.status, resp.body, resp.headers)
    if not vr.valid:
        return

    # Yalnız gözlənilmədən uğurlu olan tapıntıları bil
    if expected_fail and resp.status not in SUCCESS_CODES:
        return

    sev = "CRITICAL" if resp.status in {200, 201, 204} else "HIGH"
    finding = {
        "type":      vtype,
        "severity":  sev,
        "url":       url,
        "method":    method,
        "technique": label,
        "status":    resp.status,
        "baseline":  0,
        "reason":    reason,
        "snippet":   resp.body[:500],
        "signals":   vr.signals,
    }
    if dedup.is_new(finding):
        console.print(f"  [bold red][!] [{vtype}] {method} {url}: {resp.status}[/bold red]")
        async with lock:
            results.append(finding)


# ── Əsas modul ────────────────────────────────────────────────────────────────

async def test_access_control(url: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results = []
    lock    = asyncio.Lock()
    dedup   = Deduplicator()
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    path    = parsed.path
    query   = parsed.query

    low_hdrs  = cfg.build_headers(cfg.low_token)
    high_hdrs = cfg.build_headers(cfg.high_token) if cfg.high_token else {}
    no_auth   = {k: v for k, v in low_hdrs.items()
                 if k.lower() not in {"authorization", "cookie"}}

    validator = ResponseValidator(200, '{"ok":true}', {"Content-Type": "application/json"})

    tasks = []

    # ══════════════════════════════════════════════════════════════════════════
    # 1. ROLE/PERMISSION BYPASS — Header injection
    # Real nümunə: HackerOne — X-Admin: true ilə report silindi ($2,500)
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: role/permission header bypass...[/cyan]")
    for header, values in _ROLE_HEADERS.items():
        for val in values:
            h = {**low_hdrs, header: val}
            tasks.append(_probe(
                url, h, "GET",
                f"RoleHeader:{header}={val}",
                f"Role bypass: {header}: {val} header-i ilə admin hüququ qazanma cəhdi",
                "Role/Permission Bypass",
                client, cfg, validator, results, lock, dedup
            ))
            # POST ilə də yoxla
            tasks.append(_probe(
                url, {**h, "Content-Type": "application/json"},
                "POST",
                f"RoleHeader-POST:{header}={val}",
                f"Role bypass (POST): {header}: {val}",
                "Role/Permission Bypass",
                client, cfg, validator, results, lock, dedup,
                body={"test": True}
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # 2. HORIZONTAL IDOR/BOLA — Eyni rol, başqa istifadəçi resursu
    # Real nümunə: Twitter — başqasının DM-lərini oxu
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: horizontal IDOR/BOLA...[/cyan]")
    # URL-dəki mövcud ID-ləri tapıb dəyiş
    id_match = re.search(r'/(\d+|[0-9a-f-]{36})(?:/|$)', path)
    if id_match:
        orig_id = id_match.group(1)
        for bola_id in _BOLA_IDS:
            if bola_id == orig_id:
                continue
            new_path = path.replace(orig_id, bola_id, 1)
            test_url = urlunparse(parsed._replace(path=new_path))

            # Read IDOR
            tasks.append(_probe(
                test_url, low_hdrs, "GET",
                f"HorizIDOR:GET:{orig_id}→{bola_id}",
                f"Horizontal IDOR (Read): ID {orig_id}→{bola_id} — başqa istifadəçinin resursu",
                "Horizontal IDOR/BOLA",
                client, cfg, validator, results, lock, dedup
            ))
            # Write IDOR
            tasks.append(_probe(
                test_url, {**low_hdrs, "Content-Type": "application/json"},
                "PUT",
                f"HorizIDOR:PUT:{orig_id}→{bola_id}",
                f"Horizontal IDOR (Write): ID {orig_id}→{bola_id} — başqa resursu dəyişdir",
                "Write/Update IDOR",
                client, cfg, validator, results, lock, dedup,
                body={"data": "test"}
            ))
            # Delete IDOR
            tasks.append(_probe(
                test_url, low_hdrs, "DELETE",
                f"HorizIDOR:DELETE:{orig_id}→{bola_id}",
                f"Horizontal IDOR (Delete): ID {orig_id}→{bola_id} — başqa resursu sil",
                "Delete IDOR",
                client, cfg, validator, results, lock, dedup
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # 3. VERTICAL PRIVILEGE ESCALATION
    # Low-priv token ilə admin endpoint-lərə giriş
    # Real nümunə: Uber — driver token ilə admin endpoint ($10,000+)
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: vertical privilege escalation...[/cyan]")

    # Admin endpoint-lərini birbaşa yoxla
    admin_endpoints = [
        f"{base}/admin",
        f"{base}/api/admin",
        f"{base}/api/v1/admin",
        f"{base}/api/v1/admin/users",
        f"{base}/api/v1/users/all",
        f"{base}/api/v1/accounts/all",
        f"{base}/admin/dashboard",
        f"{base}/superadmin",
        f"{base}/api/internal/users",
        f"{base}/staff/dashboard",
    ]
    for ep in admin_endpoints:
        if cfg.allowed_scope and not any(s in ep for s in cfg.allowed_scope):
            continue
        tasks.append(_probe(
            ep, low_hdrs, "GET",
            f"VertEsc:{ep.split(base)[-1]}",
            f"Vertical escalation: low-priv token ilə admin endpoint",
            "Vertical Privilege Escalation",
            client, cfg, validator, results, lock, dedup
        ))

    # Cari path-in admin variantı
    if not path.startswith("/admin"):
        admin_var = f"{base}/admin{path}"
        tasks.append(_probe(
            admin_var, low_hdrs, "GET",
            f"VertEsc:admin-prefix",
            f"Admin prefix əlavəsi: {admin_var}",
            "Vertical Privilege Escalation",
            client, cfg, validator, results, lock, dedup
        ))

    # ══════════════════════════════════════════════════════════════════════════
    # 4. IMPROPER ACCESS CONTROL — ACL yoxlaması tam deyil
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: improper access control...[/cyan]")

    # Eyni resursa fərqli metodlarla yoxla — GET qorunur, amma PUT/DELETE yox
    for method in ["PUT", "PATCH", "DELETE", "POST"]:
        tasks.append(_probe(
            url, {**low_hdrs, "Content-Type": "application/json"},
            method,
            f"ImproperACL:{method}",
            f"Method-level ACL: GET qorunursa {method} da qorunmalıdır",
            "Method-level Authorization",
            client, cfg, validator, results, lock, dedup,
            body={"test": True} if method in {"PUT", "PATCH", "POST"} else None
        ))

    # ══════════════════════════════════════════════════════════════════════════
    # 5. API AUTHORIZATION FLAWS — REST endpoint-lərinin metod yoxlaması
    # Real nümunə: Airbnb — GET ilə qorunan endpoint-i DELETE ilə sil ($3,500)
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: API authorization flaws...[/cyan]")
    for api_path, methods in _API_AUTH_PATHS:
        api_url = urljoin(base + "/", api_path)
        for method in methods:
            tasks.append(_probe(
                api_url,
                {**low_hdrs, "Content-Type": "application/json"},
                method,
                f"APIFlaw:{method}:{api_path}",
                f"API auth flaw: {method} /{api_path} — method-level authorization yoxlanılır",
                "API Authorization Flaw",
                client, cfg, validator, results, lock, dedup,
                body={"test": True} if method in {"PUT", "PATCH", "POST"} else None
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # 6. CROSS-TENANT ACCESS
    # Multi-tenant tətbiqlərdə tenant ayrılığı yoxlaması
    # Real nümunə: GitLab — başqa tenant-ın pipeline-ına giriş ($12,000)
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: cross-tenant access...[/cyan]")
    if query:
        params = parse_qs(query)
        for field in _TENANT_FIELDS:
            if field in params:
                orig_val = params[field][0]
                if orig_val.isdigit():
                    base_int = int(orig_val)
                    for delta in [-1, 1, -2, 2]:
                        new_val = str(base_int + delta)
                        new_params = {k: v[0] for k, v in params.items()}
                        new_params[field] = new_val
                        test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                        tasks.append(_probe(
                            test_url, low_hdrs, "GET",
                            f"CrossTenant:{field}={orig_val}→{new_val}",
                            f"Cross-tenant: {field}={orig_val}→{new_val} — başqa tenant məlumatı",
                            "Cross-tenant Access",
                            client, cfg, validator, results, lock, dedup
                        ))

    # Path-dəki tenant ID-lər
    tenant_match = re.search(
        r'/(org|organization|tenant|workspace|team|company|shop)/([^/]+)',
        path, re.IGNORECASE
    )
    if tenant_match:
        orig = tenant_match.group(2)
        for alt in (["1", "2", "admin", "test"] if not orig.isdigit()
                    else [str(int(orig) + d) for d in [-1, 1]]):
            if alt == orig:
                continue
            new_path = path.replace(f"/{tenant_match.group(1)}/{orig}",
                                     f"/{tenant_match.group(1)}/{alt}", 1)
            test_url = urlunparse(parsed._replace(path=new_path))
            tasks.append(_probe(
                test_url, low_hdrs, "GET",
                f"CrossTenant-path:{orig}→{alt}",
                f"Cross-tenant path: {tenant_match.group(1)}/{orig}→{alt}",
                "Cross-tenant Access",
                client, cfg, validator, results, lock, dedup
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # 7. UNAUTHORIZED MODIFICATION & DELETION
    # Read-only istifadəçi resursu dəyişdirə/silə bilirmi?
    # ══════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] AccessControl: unauthorized modification/deletion...[/cyan]")

    # Cari URL-i PUT/PATCH/DELETE ilə yoxla
    for method, vtype in [
        ("PUT",    "Unauthorized Modification"),
        ("PATCH",  "Unauthorized Modification"),
        ("DELETE", "Unauthorized Deletion"),
    ]:
        tasks.append(_probe(
            url,
            {**low_hdrs, "Content-Type": "application/json"},
            method,
            f"UnAuth-{method}",
            f"{method} ilə icazəsiz dəyişiklik/silmə cəhdi",
            vtype,
            client, cfg, validator, results, lock, dedup,
            body={"modified": True} if method in {"PUT", "PATCH"} else None
        ))

    await asyncio.gather(*tasks)
    console.print(f"[cyan][*] Access Control: {len(results)} tapıntı[/cyan]")
    return results
