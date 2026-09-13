"""
Async HTTP Client — shared engine for all modules.
Features:
  - aiohttp session with connection pooling
  - Automatic retry on network errors
  - 429 rate-limit backoff
  - User-Agent rotation
  - Optional proxy support
  - Scope enforcement (domain whitelist)
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from rich.console import Console

from config import (
    DEFAULT_TIMEOUT, DEFAULT_RETRIES, RATE_LIMIT_SLEEP,
    USER_AGENTS, DEFAULT_HEADERS,
)

console = Console()


@dataclass
class ScanConfig:
    """Shared scan configuration passed to every module."""
    low_token:       str = ""
    high_token:      str = ""
    jwt_token:       str = ""
    extra_headers:   dict = field(default_factory=dict)
    proxy:           Optional[str] = None          # e.g. "http://127.0.0.1:8080"
    allowed_scope:   list = field(default_factory=list)   # domain whitelist
    concurrency:     int = 20
    delay:           float = 0.15
    timeout:         int = DEFAULT_TIMEOUT
    retries:         int = DEFAULT_RETRIES
    verbose:         bool = False
    wordlist_path:   Optional[str] = None
    threads:         int = 10

    def build_headers(self, token: str = "") -> dict:
        hdrs = dict(DEFAULT_HEADERS)
        hdrs["User-Agent"] = random.choice(USER_AGENTS)
        hdrs.update(self.extra_headers)
        t = token or self.low_token
        if t:
            if t.startswith("eyJ"):
                hdrs["Authorization"] = f"Bearer {t}"
            else:
                hdrs["Cookie"] = t
        return hdrs

    def in_scope(self, url: str) -> bool:
        if not self.allowed_scope:
            return True
        host = urlparse(url).hostname or ""
        return any(host == s or host.endswith("." + s) for s in self.allowed_scope)


@dataclass
class HttpResponse:
    url:      str
    method:   str
    status:   int
    body:     str
    headers:  dict
    elapsed:  float   # seconds


class AsyncClient:
    """Reusable async HTTP session wrapper."""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self._session: Optional[aiohttp.ClientSession] = None
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._request_count = 0

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=self.cfg.concurrency + 10)
        timeout   = aiohttp.ClientTimeout(total=self.cfg.timeout)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, *_):
        if self._session:
            await self._session.close()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: Optional[dict] = None,
        allow_redirects: bool = False,
    ) -> Optional[HttpResponse]:
        """Make a single HTTP request with retry + rate-limit handling."""

        if not self.cfg.in_scope(url):
            console.print(f"[yellow][~] OUT OF SCOPE — skipping: {url}[/yellow]")
            return None

        async with self._sem:
            await asyncio.sleep(self.cfg.delay)
            self._request_count += 1

            for attempt in range(self.cfg.retries + 1):
                try:
                    t0 = time.monotonic()
                    async with self._session.request(
                        method, url,
                        headers=headers,
                        json=body,
                        proxy=self.cfg.proxy,
                        allow_redirects=allow_redirects,
                        ssl=False,
                    ) as resp:
                        elapsed = time.monotonic() - t0
                        body_text = await resp.text(errors="replace")

                        if resp.status == 429:
                            wait = RATE_LIMIT_SLEEP * (attempt + 1)
                            console.print(f"[yellow][~] 429 Rate limited — sleeping {wait}s[/yellow]")
                            await asyncio.sleep(wait)
                            continue

                        return HttpResponse(
                            url=url,
                            method=method,
                            status=resp.status,
                            body=body_text,
                            headers=dict(resp.headers),
                            elapsed=elapsed,
                        )

                except (aiohttp.ClientConnectorError, asyncio.TimeoutError) as e:
                    if attempt < self.cfg.retries:
                        await asyncio.sleep(1.5 ** attempt)
                    else:
                        if self.cfg.verbose:
                            console.print(f"[dim red][-] {method} {url} failed: {e}[/dim red]")
                        return None
                except Exception as e:
                    if self.cfg.verbose:
                        console.print(f"[dim red][-] Unexpected error {url}: {e}[/dim red]")
                    return None
        return None

    async def get(self, url: str, headers: dict, **kw) -> Optional[HttpResponse]:
        return await self.request("GET", url, headers, **kw)

    @property
    def total_requests(self) -> int:
        return self._request_count
