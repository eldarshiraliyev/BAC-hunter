"""
Workflow & Multi-Step Authorization Module
==========================================
Əhatə etdiyi kateqoriyalar:
  - Multi-step/workflow authorization bypass
  - Unauthorized function execution
  - File/object authorization
  - Hidden endpoint access
  - Unauthenticated authorization bypass

Real bug bounty nümunələri:
  - Shopify: checkout step-i atla ($X → $0 ödəniş)
  - HackerOne: step 2-ni tamamlamadan step 3-ə keç
  - Gitlab: pipeline approval-ı bypass et
  - PayPal: payment confirm endpoint-i birbaşa çağır
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin, urlunparse

from rich.console import Console

from config import SUCCESS_CODES, FORBIDDEN_CODES
from modules.http_client import AsyncClient, ScanConfig
from modules.validator import ResponseValidator, Deduplicator

console = Console()

# ── Workflow endpoint pattern-ları ────────────────────────────────────────────
# Bu path segment-ləri multi-step flow-un addımlarını göstərir
_STEP_PATTERNS = re.compile(
    r'/(step|stage|phase|wizard|flow|checkout|confirm|complete|'
    r'verify|approve|submit|finalize|publish|activate|process)[\-_/]?(\d+|[a-z]+)?',
    re.IGNORECASE,
)

# ── Funksiya endpoint-ləri ────────────────────────────────────────────────────
# Yüksək risk daşıyan action endpoint-ləri
_FUNCTION_PATHS = [
    # Admin funksiyaları
    "delete", "destroy", "remove", "purge", "wipe",
    "approve", "reject", "verify", "activate", "deactivate",
    "suspend", "ban", "unban", "promote", "demote",
    "reset", "reset-password", "force-reset",
    "publish", "unpublish", "archive", "restore",
    "export", "download", "generate",
    "assign", "unassign", "transfer", "move",
    "merge", "split", "clone", "duplicate",
    "send", "broadcast", "notify", "alert",
    "lock", "unlock", "enable", "disable",
    "impersonate", "login-as", "su", "switch-user",
    # Payment funksiyaları
    "charge", "refund", "cancel", "void",
    "checkout/complete", "payment/confirm", "order/finalize",
    # API admin
    "api/v1/admin/action", "api/v1/users/promote",
    "api/v1/orders/approve", "api/v1/payments/process",
]

# ── File/Object path pattern-ları ────────────────────────────────────────────
_FILE_EXTENSIONS = [
    ".pdf", ".docx", ".xlsx", ".zip", ".tar.gz",
    ".sql", ".csv", ".json", ".xml", ".log",
    ".jpg", ".png", ".mp4", ".mp3",
    ".key", ".pem", ".cert", ".env", ".config",
]

_FILE_PATHS = [
    "files", "uploads", "documents", "attachments",
    "media", "assets", "static", "download",
    "api/v1/files", "api/v1/documents", "api/files",
    "storage", "blob", "s3", "cdn",
]

# ── Unauthenticated bypass endpoint-ləri ─────────────────────────────────────
_UNAUTH_PATHS = [
    # Açıq olmamalı olan admin/internal endpoint-lər
    "api/internal/users", "api/internal/admin",
    "api/debug/users", "api/debug/config",
    "internal/api/users", "internal/metrics",
    "_internal", "_admin", "_debug",
    # Health check-lər həssas məlumat ifşa edə bilər
    "health", "healthz", "health/detail",
    "status", "status/detail", "ping",
    "metrics", "prometheus/metrics",
    # Swagger/OpenAPI
    "swagger.json", "openapi.json", "api-docs",
    # Callback URL-lər
    "callback", "webhook", "hook", "notify",
    "oauth/callback", "auth/callback",
    # Password reset flow
    "forgot-password", "reset-password",
    "api/v1/auth/reset", "api/v1/auth/verify",
]


# ── Step/flow aşkarlanması ────────────────────────────────────────────────────

def _detect_workflow_steps(url: str) -> list[dict]:
    """URL-dən workflow addımlarını çıxar."""
    parsed = urlparse(url)
    path   = parsed.path
    steps  = []

    for m in _STEP_PATTERNS.finditer(path):
        steps.append({
            "keyword": m.group(1),
            "value":   m.group(2) or "",
            "span":    m.span(0),
            "full":    m.group(0),
        })
    return steps


def _build_skip_urls(url: str, steps: list[dict]) -> list[tuple[str, str]]:
    """
    Workflow step-lərini atlamaq üçün URL-lər yarat.
    Məs: /checkout/step2 → /checkout/step3 (step2-ni tamamlamadan)
    """
    parsed  = urlparse(url)
    path    = parsed.path
    results = []

    for step in steps:
        kw  = step["keyword"]
        val = step["value"]

        if val.isdigit():
            # Rəqəmsal addım: irəli atla
            for jump in [1, 2, 3]:
                new_val  = str(int(val) + jump)
                new_full = step["full"].replace(val, new_val)
                new_path = path[:step["span"][0]] + new_full + path[step["span"][1]:]
                new_url  = urlunparse(parsed._replace(path=new_path))
                results.append((new_url, f"Workflow skip: {kw}{val}→{kw}{new_val}"))
        else:
            # Mətn addımı: son addıma atla
            for final in ["confirm", "complete", "finalize", "finish", "submit"]:
                if val.lower() != final:
                    new_full = step["full"].replace(val, final) if val else f"/{kw}/{final}"
                    new_path = path[:step["span"][0]] + new_full + path[step["span"][1]:]
                    new_url  = urlunparse(parsed._replace(path=new_path))
                    results.append((new_url, f"Workflow skip: {kw}/{val}→{kw}/{final}"))

    return results


# ── Əsas modul ────────────────────────────────────────────────────────────────

async def test_workflow_auth(url: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results = []
    lock    = asyncio.Lock()
    dedup   = Deduplicator()
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    path    = parsed.path

    low_hdrs  = cfg.build_headers(cfg.low_token)
    no_auth   = {k: v for k, v in low_hdrs.items()
                 if k.lower() not in {"authorization", "cookie"}}

    validator = ResponseValidator(200, "", {"Content-Type": "application/json"})

    async def probe(test_url: str, hdrs: dict, label: str, reason: str,
                    vtype: str, method: str = "GET", body: dict = None):
        resp = await client.request(method, test_url, hdrs,
                                    body=body, allow_redirects=True)
        if not resp:
            return

        if cfg.verbose:
            console.print(f"  [dim][{vtype}] {method} {test_url}: {resp.status}[/dim]")

        vr = validator.validate(resp.status, resp.body, resp.headers)
        if not vr.valid:
            return

        sev = "CRITICAL" if resp.status in SUCCESS_CODES else "HIGH"
        finding = {
            "type":      vtype,
            "severity":  sev,
            "url":       test_url,
            "method":    method,
            "technique": label,
            "status":    resp.status,
            "baseline":  0,
            "reason":    reason,
            "snippet":   resp.body[:500],
        }
        if dedup.is_new(finding):
            console.print(f"  [bold red][!] [{vtype}] {label}: HTTP {resp.status}[/bold red]")
            async with lock:
                results.append(finding)

    tasks = []

    # ── 1. Multi-step workflow bypass ─────────────────────────────────────────
    console.print("[cyan][*] Workflow: multi-step bypass testləri...[/cyan]")
    steps = _detect_workflow_steps(url)
    if steps:
        console.print(f"[cyan][*] Workflow addımları aşkarlandı: {[s['full'] for s in steps]}[/cyan]")
        for skip_url, label in _build_skip_urls(url, steps):
            tasks.append(probe(
                skip_url, low_hdrs, label,
                f"Workflow addımı atlandı: {label} — state machine bypass",
                "Multi-step Auth Bypass"
            ))
    else:
        # Cari URL-dəki ümumi flow keyword-lərini tap
        for kw in ["confirm", "complete", "finalize", "approve", "submit"]:
            test_url = urljoin(base + path.rstrip("/") + "/", kw)
            tasks.append(probe(
                test_url, low_hdrs,
                f"DirectAccess:/{kw}",
                f"Workflow son addımına birbaşa giriş: /{kw}",
                "Multi-step Auth Bypass"
            ))

    # ── 2. Unauthorized function execution ────────────────────────────────────
    console.print("[cyan][*] Workflow: unauthorized function execution...[/cyan]")
    for func_path in _FUNCTION_PATHS:
        for method in ["POST", "GET"]:
            test_url = urljoin(base + "/", func_path)
            tasks.append(probe(
                test_url, low_hdrs,
                f"FuncExec:{func_path}",
                f"İcazəsiz funksiya çağırışı: {method} /{func_path}",
                "Unauthorized Function Execution",
                method=method
            ))

    # ── 3. File/Object authorization ──────────────────────────────────────────
    console.print("[cyan][*] Workflow: file/object authorization...[/cyan]")
    for file_path in _FILE_PATHS:
        test_url = urljoin(base + "/", file_path)
        tasks.append(probe(
            test_url, low_hdrs,
            f"FileAccess:{file_path}",
            f"File endpoint icazə yoxlaması: /{file_path}",
            "File/Object Authorization"
        ))
        # ID ilə spesifik fayl
        for fid in ["1", "2", "100", "../etc/passwd"]:
            tasks.append(probe(
                f"{test_url}/{fid}", low_hdrs,
                f"FileID:{file_path}/{fid}",
                f"Fayl ID manipulyasiyası: /{file_path}/{fid}",
                "File/Object Authorization"
            ))

    # Fayl endirmə extension-ları
    for ext in _FILE_EXTENSIONS[:6]:  # ilk 6 ən kritik
        for base_name in ["report", "backup", "export", "data", "users"]:
            tasks.append(probe(
                urljoin(base + "/", f"download/{base_name}{ext}"),
                low_hdrs,
                f"FileDownload:{base_name}{ext}",
                f"İcazəsiz fayl endirməsi: /download/{base_name}{ext}",
                "File/Object Authorization"
            ))

    # ── 4. Hidden endpoint access ─────────────────────────────────────────────
    console.print("[cyan][*] Workflow: hidden endpoint discovery...[/cyan]")
    # Cari path-dən gizli endpoint törət
    path_parts = [p for p in path.split("/") if p]
    if path_parts:
        last_part = path_parts[-1]
        parent    = "/" + "/".join(path_parts[:-1]) if len(path_parts) > 1 else "/"

        # Eyni resursun admin/debug variantları
        for suffix in ["_admin", "_debug", "_internal", "_backup",
                        "/admin", "/debug", "/raw", "/export", "/all"]:
            tasks.append(probe(
                urljoin(base + parent + "/", last_part + suffix),
                low_hdrs,
                f"HiddenEP:{suffix}",
                f"Gizli endpoint variant: {last_part}{suffix}",
                "Hidden Endpoint Access"
            ))

    # ── 5. Unauthenticated bypass ─────────────────────────────────────────────
    console.print("[cyan][*] Workflow: unauthenticated access testləri...[/cyan]")
    for unauth_path in _UNAUTH_PATHS:
        test_url = urljoin(base + "/", unauth_path)
        # Həm token-siz, həm də low-priv ilə yoxla
        tasks.append(probe(
            test_url, no_auth,
            f"Unauth:/{unauth_path}",
            f"Token olmadan əlçatan endpoint: /{unauth_path}",
            "Unauthenticated Auth Bypass"
        ))

    # Cari URL token-siz əlçatandırmı?
    tasks.append(probe(
        url, no_auth,
        "Unauth:current-url",
        f"Cari URL token olmadan əlçatandırmı?",
        "Unauthenticated Auth Bypass"
    ))

    await asyncio.gather(*tasks)
    console.print(f"[cyan][*] Workflow/Function auth: {len(results)} tapıntı[/cyan]")
    return results
