"""
Forced Browsing Module v2.1
──────────────────────────
Əsas dəyişiklik: redirect izləmə + dərin yoxlama (deep validation).

Axın:
  1. İlk sorğu allow_redirects=False — redirect zəncirini görürük
  2. Əgər 3xx → redirect-i izlə, son nöqtənin statusunu al
  3. Son status 200 deyilsə → false positive, keç
  4. Son status 200-dürsa → məzmunu yoxla:
       - Login/error səhifəsinə düşmüşükmü? (keyword filter)
       - Soft-404 barmaqiziylə eynidir? (body-length filter)
       - Content-Type HTML-dirsə və body boşdursa? → keç
  5. Yalnız bütün yoxlamalardan keçənlər reporta düşür
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TaskProgressColumn, TextColumn, TimeElapsedColumn,
)

from config import BUILTIN_WORDLIST, SUCCESS_CODES
from modules.http_client import AsyncClient, ScanConfig

console = Console()

# ── Məzmun yoxlama ────────────────────────────────────────────────────────────

# Bu keyword-lərdən biri body-dədirsə, çox güman ki login/error səhifəsidir
_LOGIN_KEYWORDS = re.compile(
    r'(login|sign.?in|log.?in|authenticate|unauthorized|access.denied'
    r'|forbidden|not.found|404|page.not.found|oops|error.occurred'
    r'|<title>[^<]*(login|sign in|error|not found|forbidden)[^<]*</title>)',
    re.IGNORECASE,
)

# Minimum məzmun uzunluğu — bundan qısa body real endpoint deyil
_MIN_BODY_LEN = 100


def _seems_real(body: str, content_type: str) -> tuple[bool, str]:
    """
    Cavabın real, əlçatan məzmun olub-olmadığını yoxla.
    (True, "") → real tapıntı
    (False, səbəb) → false positive
    """
    if len(body) < _MIN_BODY_LEN:
        return False, f"body too short ({len(body)}B — likely empty or redirect page)"

    if _LOGIN_KEYWORDS.search(body):
        return False, "body contains login/error keywords — likely redirected to auth page"

    return True, ""


# ── Wordlist ──────────────────────────────────────────────────────────────────

import os

# Tool-un öz wordlist qovluğu
_WL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")

# Avtomatik axtarış sırası — hansı tapılsa o istifadə edilir
_AUTO_WORDLISTS = [
    os.path.join(_WL_DIR, "bac-hunter-combined.txt"),   # birləşdirilmiş (48k)
    os.path.join(_WL_DIR, "raft-medium-directories.txt"), # SecLists raft
    os.path.join(_WL_DIR, "common.txt"),                  # SecLists common
    # Sistem quraşdırılmış SecLists (Kali/Parrot/Ubuntu)
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def _read_file(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [
            l.strip().lstrip("/")
            for l in f
            if l.strip() and not l.startswith("#")
        ]


def load_wordlist(path: str | None) -> list[str]:
    # 1. İstifadəçi açıq fayl göstərib
    if path:
        try:
            words = _read_file(path)
            console.print(f"[cyan][*] Wordlist: {len(words):,} söz ← {path}[/cyan]")
            return words
        except FileNotFoundError:
            console.print(f"[yellow][~] Wordlist tapılmadı: {path}[/yellow]")

    # 2. Avtomatik axtarış
    for candidate in _AUTO_WORDLISTS:
        if os.path.exists(candidate):
            words = _read_file(candidate)
            console.print(f"[cyan][*] Wordlist (avtomatik): {len(words):,} söz ← {candidate}[/cyan]")
            return words

    # 3. Son çıxış yolu — config-dəki daxili siyahı
    console.print(
        f"[yellow][~] Xarici wordlist tapılmadı — daxili siyahı istifadə edilir "
        f"({len(BUILTIN_WORDLIST)} söz).[/yellow]\n"
        f"[dim]    Tövsiyə: python main.py ... --wordlist wordlists/bac-hunter-combined.txt[/dim]"
    )
    return BUILTIN_WORDLIST


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ── Əsas skan funksiyası ──────────────────────────────────────────────────────

async def test_forced_browse(url: str, client: AsyncClient, cfg: ScanConfig) -> list[dict]:
    results  = []
    lock     = asyncio.Lock()
    base     = _base_url(url)
    wordlist = load_wordlist(cfg.wordlist_path)

    # ── Soft-404 barmaqizi ────────────────────────────────────────────────────
    # allow_redirects=True ilə — real 404 body-ni görürük
    canary_url  = urljoin(base + "/", "bac_hunter_canary_xqz_notreal_9f3k")
    canary_hdrs = cfg.build_headers(cfg.low_token)
    canary_resp = await client.get(canary_url, canary_hdrs, allow_redirects=True)

    canary_body_sig = ""
    if canary_resp and canary_resp.status == 200:
        canary_body_sig = str(len(canary_resp.body))
        console.print(
            f"[yellow][~] Soft-404 aşkarlandı — server hər URL-ə 200 qaytarır. "
            f"Body-length filtr aktiv ({canary_body_sig}B).[/yellow]"
        )

    console.print(
        f"[cyan][*] Forced browse başladı: {base} | "
        f"{len(wordlist)} yol | redirect izləmə: aktiv[/cyan]"
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Forced Browse[/cyan]"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning", total=len(wordlist))

        async def probe(word: str):
            test_url = urljoin(base + "/", word.lstrip("/"))
            hdrs     = cfg.build_headers(cfg.low_token)
            progress.advance(task)

            # ── Mərhələ 1: redirect izləmədən ilk sorğu ──────────────────────
            first = await client.get(test_url, hdrs, allow_redirects=False)
            if not first:
                return

            initial_status = first.status

            # 404, 401, 403, 405 → maraqlı deyil, keç
            if initial_status in {404, 401, 405, 500, 503}:
                if cfg.verbose:
                    console.print(f"  [dim]skip [{initial_status}] {test_url}[/dim]")
                return

            # ── Mərhələ 2: redirect varsa, son nöqtəyə get ───────────────────
            final_resp = first
            redirect_chain = []

            if initial_status in {301, 302, 303, 307, 308}:
                location = first.headers.get("Location") or first.headers.get("location", "")
                if location:
                    # Nisbi URL-i mütləqə çevir
                    if location.startswith("/"):
                        location = f"{urlparse(test_url).scheme}://{urlparse(test_url).netloc}{location}"
                    redirect_chain.append(f"{initial_status} → {location}")

                    # Son nöqtəyə allow_redirects=True ilə get
                    followed = await client.get(test_url, hdrs, allow_redirects=True)
                    if not followed:
                        if cfg.verbose:
                            console.print(f"  [dim]redirect izlənə bilmədi: {test_url}[/dim]")
                        return
                    final_resp = followed

            final_status = final_resp.status

            # ── Mərhələ 3: son status yalnız 200/201/204 olmalıdır ────────────
            if final_status not in SUCCESS_CODES:
                if cfg.verbose:
                    redirect_info = f" → {final_status}" if redirect_chain else ""
                    console.print(
                        f"  [dim]false positive: [{initial_status}]{redirect_info} {test_url}[/dim]"
                    )
                return

            # ── Mərhələ 4: məzmun yoxlaması ───────────────────────────────────
            body         = final_resp.body
            content_type = final_resp.headers.get("Content-Type", "")

            # Soft-404 filtr
            if canary_body_sig and str(len(body)) == canary_body_sig:
                if cfg.verbose:
                    console.print(f"  [dim]soft-404 filtered: {test_url}[/dim]")
                return

            # Məzmun analizi
            real, skip_reason = _seems_real(body, content_type)
            if not real:
                if cfg.verbose:
                    console.print(f"  [dim]content filter [{initial_status}→{final_status}]: {skip_reason} — {test_url}[/dim]")
                return

            # ── Tapıntı! ──────────────────────────────────────────────────────
            redirect_note = ""
            if redirect_chain:
                redirect_note = f" (redirect: {' → '.join(redirect_chain)})"

            console.print(
                f"  [bold red][!] [{initial_status}→{final_status}] {test_url}[/bold red]"
                f"[dim]{redirect_note}[/dim]"
            )

            async with lock:
                results.append({
                    "type":     "Forced Browsing",
                    "severity": "HIGH",
                    "url":      test_url,
                    "status":   final_status,
                    "initial_status": initial_status,
                    "redirect_chain": redirect_chain,
                    "size":     len(body.encode()),
                    "reason":   (
                        f"Endpoint real məzmunla əlçatandır"
                        f"{redirect_note} → son status HTTP {final_status}"
                    ),
                    "snippet":  body[:500],
                })

        await asyncio.gather(*[probe(w) for w in wordlist])

    console.print(f"[cyan][*] Forced browse tamamlandı: {len(results)} real tapıntı[/cyan]")
    return results
