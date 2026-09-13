"""
Recon Module — Universal endpoint kəşfi

Bug bounty-də tool-u universal etmək üçün lazımdır:
  1. URL siyahısından oxuma (--urls-file)
  2. HAR faylından endpoint çıxarma (Burp/Chrome export)
  3. Burp Suite XML export-dan endpoint çıxarma
  4. Saytı crawl edib endpoint-ləri tap
  5. JS fayllarından API endpoint çıxarma

Output: test ediləcək URL-lərin siyahısı
"""

import json
import re
import xml.etree.ElementTree as ET
from base64 import b64decode
from urllib.parse import urlparse, urljoin
from pathlib import Path

from rich.console import Console

console = Console()

# ── API endpoint pattern-ları JS-dən çıxarmaq üçün ──────────────────────────
_API_IN_JS = re.compile(
    r'(?:fetch|axios|http\.get|http\.post|api\.|apiUrl|baseURL|endpoint)\s*'
    r'[(`\'"]'
    r'(/[a-zA-Z0-9/_\-\.?=&%{}:]+)',
    re.IGNORECASE,
)

_URL_IN_JS = re.compile(
    r'["`\'](/(?:api|v\d|graphql|admin|internal|users?|accounts?|'
    r'orders?|products?)[a-zA-Z0-9/_\-\.?=&%]*)["`\']',
    re.IGNORECASE,
)


def load_urls_file(path: str) -> list[str]:
    """
    Bir sətirdə bir URL olan fayl oxu.
    Boş sətir və # ilə başlayan sətirləri keç.
    """
    try:
        urls = []
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and not u.startswith("#") and u.startswith("http"):
                    urls.append(u)
        console.print(f"[cyan][*] URL fayl: {len(urls)} URL ← {path}[/cyan]")
        return urls
    except FileNotFoundError:
        console.print(f"[red][-] URL fayl tapılmadı: {path}[/red]")
        return []


def parse_har(path: str, scope: list[str] = None) -> list[dict]:
    """
    HAR (HTTP Archive) faylından bütün sorğuları çıxar.
    Browser DevTools → Network → Export HAR ilə əldə edilir.

    Returns: [{"url": ..., "method": ..., "headers": ..., "body": ...}]
    """
    try:
        with open(path, encoding="utf-8") as f:
            har = json.load(f)
    except Exception as e:
        console.print(f"[red][-] HAR parse xətası: {e}[/red]")
        return []

    entries = har.get("log", {}).get("entries", [])
    results = []

    for entry in entries:
        req = entry.get("request", {})
        url = req.get("url", "")
        if not url:
            continue

        # Scope yoxlaması
        if scope:
            host = urlparse(url).hostname or ""
            if not any(host == s or host.endswith("." + s) for s in scope):
                continue

        # Static resursları keç
        if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|css|woff|woff2|ttf|map)(\?|$)',
                     url, re.IGNORECASE):
            continue

        method  = req.get("method", "GET").upper()
        headers = {h["name"]: h["value"] for h in req.get("headers", [])}

        # POST body
        body = None
        post_data = req.get("postData", {})
        if post_data and post_data.get("text"):
            try:
                body = json.loads(post_data["text"])
            except Exception:
                body = post_data["text"]

        results.append({
            "url":     url,
            "method":  method,
            "headers": headers,
            "body":    body,
        })

    console.print(f"[cyan][*] HAR: {len(results)} endpoint tapıldı ← {path}[/cyan]")
    return results


def parse_burp_xml(path: str, scope: list[str] = None) -> list[dict]:
    """
    Burp Suite XML export-dan sorğuları çıxar.
    Burp → Proxy → HTTP history → Save items → XML
    """
    results = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as e:
        console.print(f"[red][-] Burp XML parse xətası: {e}[/red]")
        return []

    for item in root.findall(".//item"):
        url_el    = item.find("url")
        method_el = item.find("method")
        req_el    = item.find("request")

        if url_el is None:
            continue
        url = url_el.text or ""
        if not url:
            continue

        # Scope
        if scope:
            host = urlparse(url).hostname or ""
            if not any(host == s or host.endswith("." + s) for s in scope):
                continue

        # Static keç
        if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|css|woff|ttf|map)(\?|$)',
                     url, re.IGNORECASE):
            continue

        method = (method_el.text or "GET").upper()

        # Raw request decode
        headers, body = {}, None
        if req_el is not None:
            raw = req_el.text or ""
            # Burp base64 encode edir
            try:
                is_b64 = req_el.get("base64", "false").lower() == "true"
                if is_b64:
                    raw = b64decode(raw).decode("utf-8", errors="replace")
            except Exception:
                pass
            # Header-ları parse et
            lines = raw.split("\n")
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.strip()] = v.strip()
                elif not line.strip():
                    break
            # Body (son boş sətirdən sonra)
            parts = raw.split("\r\n\r\n", 1) if "\r\n\r\n" in raw else raw.split("\n\n", 1)
            if len(parts) > 1 and parts[1].strip():
                try:
                    body = json.loads(parts[1])
                except Exception:
                    body = parts[1].strip()

        results.append({
            "url":     url,
            "method":  method,
            "headers": headers,
            "body":    body,
        })

    console.print(f"[cyan][*] Burp XML: {len(results)} endpoint tapıldı ← {path}[/cyan]")
    return results


def extract_from_js(js_content: str, base_url: str) -> list[str]:
    """JS faylından API endpoint-ləri çıxar."""
    urls = set()
    base = urlparse(base_url)
    origin = f"{base.scheme}://{base.netloc}"

    for m in _API_IN_JS.finditer(js_content):
        path = m.group(1)
        if path and len(path) > 2:
            urls.add(urljoin(origin, path.split("{")[0]))

    for m in _URL_IN_JS.finditer(js_content):
        path = m.group(1)
        if path and len(path) > 2:
            urls.add(urljoin(origin, path.split("{")[0]))

    return list(urls)


def deduplicate_urls(urls: list[str]) -> list[str]:
    """URL-ləri deduplicate et — eyni path, fərqli query variantları qal."""
    seen_paths = set()
    result = []
    for url in urls:
        parsed = urlparse(url)
        # Path + query key-ləri əsasında dedup
        qkeys = "&".join(sorted(k for k, _ in
                                (p.split("=", 1) for p in parsed.query.split("&") if "=" in p)))
        sig = f"{parsed.netloc}{parsed.path}?{qkeys}"
        if sig not in seen_paths:
            seen_paths.add(sig)
            result.append(url)
    return result


def load_all_targets(args, base_url: str, scope: list[str]) -> list[dict]:
    """
    Bütün mənbələrdən target-ləri yığ.
    Returns: [{"url": ..., "method": ..., "headers": ..., "body": ...}]
    """
    targets = []

    # 1. Əsas URL həmişə var
    targets.append({"url": base_url, "method": "GET", "headers": {}, "body": None})

    # 2. URL siyahısı faylı
    if hasattr(args, "urls_file") and args.urls_file:
        for u in load_urls_file(args.urls_file):
            targets.append({"url": u, "method": "GET", "headers": {}, "body": None})

    # 3. HAR fayl
    if hasattr(args, "har") and args.har:
        targets.extend(parse_har(args.har, scope))

    # 4. Burp XML
    if hasattr(args, "burp") and args.burp:
        targets.extend(parse_burp_xml(args.burp, scope))

    # Dedup
    seen = set()
    unique = []
    for t in targets:
        k = f"{t['method']}|{t['url']}"
        if k not in seen:
            seen.add(k)
            unique.append(t)

    console.print(f"[cyan][*] Cəmi {len(unique)} unikal target toplandı[/cyan]")
    return unique
