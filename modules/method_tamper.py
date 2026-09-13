"""
HTTP Method Tampering Module v3 — Validator, redirect izləmə, daha dəqiq
"""

import asyncio
from rich.console import Console

from config import HTTP_METHODS, METHOD_OVERRIDE_HEADERS, FORBIDDEN_CODES, SUCCESS_CODES
from modules.http_client import AsyncClient, ScanConfig
from modules.validator import ResponseValidator, Deduplicator

console = Console()

DESTRUCTIVE = {"DELETE", "PUT", "PATCH"}


async def test_method_tampering(url: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results = []
    lock    = asyncio.Lock()
    dedup   = Deduplicator()

    hdrs = cfg.build_headers(cfg.low_token)

    # ── Baseline: GET ─────────────────────────────────────────────────────────
    baseline = await client.get(url, hdrs, allow_redirects=True)
    if not baseline:
        console.print(f"[red][-] Method tamper: {url} əlçatan deyil[/red]")
        return results

    bs = baseline.status
    console.print(f"[cyan][*] Method tamper baseline GET → {bs}[/cyan]")

    validator = ResponseValidator(bs, baseline.body, baseline.headers)

    async def probe(method: str, test_url: str, probe_hdrs: dict, label: str):
        resp = await client.request(method, test_url, probe_hdrs, allow_redirects=True)
        if not resp:
            return

        if cfg.verbose:
            console.print(f"  [dim]{label} → {resp.status}[/dim]")

        is_finding = False
        severity   = "MEDIUM"
        reason     = ""

        # Pattern 1: GET forbidden idi, başqa metod ilə açıldı
        if bs in FORBIDDEN_CODES and resp.status in SUCCESS_CODES:
            vr = validator.validate(resp.status, resp.body, resp.headers, mode="generic",
                                    need_status=SUCCESS_CODES)
            if vr.valid:
                is_finding = True
                severity   = "HIGH"
                reason     = f"GET→{bs} amma {method}→{resp.status}: giriş nəzarəti bypass"

        # Pattern 2: Destruktiv metod qəbul edildi
        elif method in DESTRUCTIVE and resp.status in SUCCESS_CODES:
            vr = validator.validate(resp.status, resp.body, resp.headers)
            if vr.valid:
                is_finding = True
                severity   = "MEDIUM"
                reason     = f"{method} metodu qəbul edildi (HTTP {resp.status}) — data dəyişikliyi riski"

        # Pattern 3: TRACE aktiv + auth header leakage
        elif method == "TRACE" and resp.status == 200:
            if "authorization" in resp.body.lower() or "cookie" in resp.body.lower():
                is_finding = True
                severity   = "MEDIUM"
                reason     = "TRACE aktiv — auth header-lər cavabda əks olunur (XST riski)"

        if is_finding:
            finding = {
                "type":     "HTTP Method Tampering",
                "severity": severity,
                "url":      test_url,
                "method":   label,
                "status":   resp.status,
                "baseline": bs,
                "reason":   reason,
                "snippet":  resp.body[:500],
            }
            if dedup.is_new(finding):
                console.print(f"  [bold red][!] {label} → {resp.status}: {reason}[/bold red]")
                async with lock:
                    results.append(finding)

    tasks = []

    # Bütün HTTP metodları
    for method in HTTP_METHODS:
        if method == "GET":
            continue
        tasks.append(probe(method, url, dict(hdrs), f"{method}"))

    # Method-override header-ları
    for hdr in METHOD_OVERRIDE_HEADERS:
        for method in ["DELETE", "PUT", "PATCH", "ADMIN"]:
            tasks.append(probe(
                "GET", url,
                {**hdrs, hdr: method},
                f"GET+{hdr}:{method}"
            ))

    await asyncio.gather(*tasks)
    return results
