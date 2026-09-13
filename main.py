#!/usr/bin/env python3
"""
BAC Hunter v3 — Authorization Intelligence Engine
Bug Bounty Edition

Sadə scanner yox — authorization evidence engine:
  WHO (actor) → WHAT (resource) → ACTION → EXPECTED → ACTUAL → CONFIDENCE

20 kateqoriya:
  BOLA/Horizontal IDOR    | BFLA/Vertical PrivEsc  | BOPLA/Property Exposure
  Cross-Tenant Access     | Write/Update IDOR       | Delete IDOR
  Role/Permission Bypass  | Method-Level Auth       | Unauthorized Function Exec
  Workflow/State Bypass   | GraphQL Auth            | Bulk Authorization
  Unauthenticated Bypass  | Hidden Endpoint Access  | File/Object Auth
  JWT Authorization       | API Version Auth        | Mass Assignment
  REST API Auth Flaws     | Multi-Step Auth Bypass

Rejimlər:
  --mode safe    → yalnız GET/HEAD/OPTIONS (read-only)
  --mode active  → POST/PUT/PATCH/DELETE (default — yalnız test account ilə)

Nümunələr:
  python main.py --url https://target.com/api/users/42 \\
    --token eyJ_user... --admin-token eyJ_admin... --all --report

  python main.py --url https://target.com/api/orders/123 \\
    --token eyJ... --mode safe --idor --rbac

  python main.py --url https://target.com \\
    --forced-browse --wordlist wordlists/bac-hunter-combined.txt

  python main.py --url https://target.com/api/v1/users/5 \\
    --token eyJ... --admin-token eyJ_admin... --all \\
    --proxy http://127.0.0.1:8080 --scope target.com --report
"""

import argparse
import asyncio
import sys
import os

from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box

sys.path.insert(0, os.path.dirname(__file__))

from config import BANNER
from core.engine import BACEngine, ScanMode
from modules.http_client import ScanConfig
from modules.reporter import print_terminal_summary, save_reports

console = Console()


def parse_headers(raw: list[str]) -> dict:
    hdrs = {}
    for item in (raw or []):
        if ":" in item:
            k, v = item.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return hdrs


def print_scan_header(actor_low, actor_high, mode: str):
    console.print()
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column("", style="dim cyan")
    t.add_column("")
    t.add_row("Actor (low-priv)",
              f"{actor_low.identity} | role={actor_low.role} | tenant={actor_low.tenant_id or '?'}")
    if actor_high and actor_high.identity not in {"none", "anonymous"}:
        t.add_row("Actor (high-priv)",
                  f"{actor_high.identity} | role={actor_high.role}")
    t.add_row("Scan Mode", mode.upper())
    console.print(t)
    console.print()


def print_root_causes(root_causes: list[dict]):
    if not root_causes:
        return
    console.print(Rule("[bold]Root Cause Analizi[/bold]"))
    t = Table(box=box.ROUNDED, border_style="dim white", show_header=True,
              header_style="bold cyan")
    t.add_column("Root Cause", width=10)
    t.add_column("Vuln Class",  width=30)
    t.add_column("Endpoint",    no_wrap=False)
    t.add_column("Affected", width=8)
    for rc in root_causes[:10]:
        t.add_row(
            rc["root_cause"],
            rc["vuln_class"],
            rc["normalized_url"],
            str(rc["count"]),
        )
    console.print(t)


def print_stats(stats: dict):
    console.print()
    console.print(
        f"[bold]Skan statistikası:[/bold]\n"
        f"  Ümumi sorğu:        [cyan]{stats.get('requests', 0)}[/cyan]\n"
        f"  Ham tapıntı:        {stats.get('total_raw', 0)}\n"
        f"  Root-cause dedup:   [green]{stats.get('total_findings', 0)}[/green] "
        f"([dim]FP filter: {stats.get('fp_filter_rate', 'N/A')}[/dim])\n"
        f"  Root cause sayı:    {stats.get('root_causes', 0)}\n"
        f"  Object graph:       {stats.get('objects_in_graph', 0)} object\n"
        f"  Skan müddəti:       [cyan]{stats.get('elapsed_s', 0)}s[/cyan]"
    )
    console.print()


async def run(args) -> tuple[list[dict], dict, list[dict]]:
    cfg = ScanConfig(
        low_token     = args.token or "",
        high_token    = args.admin_token or "",
        jwt_token     = args.jwt or args.token or "",
        extra_headers = parse_headers(args.header),
        proxy         = args.proxy or None,
        allowed_scope = [s.strip() for s in (args.scope or "").split(",") if s.strip()],
        concurrency   = args.concurrency,
        delay         = args.delay,
        timeout       = args.timeout,
        retries       = args.retries,
        verbose       = args.verbose,
        wordlist_path = args.wordlist,
        threads       = args.threads,
    )

    mode = getattr(args, "mode", ScanMode.ACTIVE)
    run_all = args.all

    engine = BACEngine(url=args.url, cfg=cfg, mode=mode)

    result = await engine.run(
        run_bola     = run_all or args.idor,
        run_rbac     = run_all or args.rbac,
        run_workflow = run_all or args.workflow,
        run_browse   = run_all or args.forced_browse,
        run_method   = run_all or args.method_tamper,
        run_jwt      = run_all or args.jwt_attack,
        run_access   = run_all or args.access_control,
    )

    # Actor məlumatlarını ekrana çap et
    if result.actor_low:
        print_scan_header(result.actor_low, result.actor_high, mode)

    return result.findings, result.stats, result.root_causes


def main():
    console.print(f"[bold red]{BANNER}[/bold red]")

    p = argparse.ArgumentParser(
        prog="bac-hunter",
        description="BAC Hunter v3 — Authorization Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    g = p.add_argument_group("Hədəf")
    g.add_argument("--url",          required=True)
    g.add_argument("--token",        default="", help="Low-priv token (JWT/Cookie)")
    g.add_argument("--admin-token",  default="", help="High-priv token")
    g.add_argument("--jwt",          default="", help="JWT token (JWT module üçün)")
    g.add_argument("-H","--header",  action="append", metavar="'K: V'")

    m = p.add_argument_group("Modullar")
    m.add_argument("--all",            action="store_true", help="Bütün modullar")
    m.add_argument("--idor",           action="store_true", help="BOLA/IDOR (read+write+delete+BOPLA)")
    m.add_argument("--access-control", action="store_true", help="Universal access control (20 kateqoriya)")
    m.add_argument("--rbac",           action="store_true", help="RBAC bypass")
    m.add_argument("--workflow",       action="store_true", help="Workflow/function/file auth")
    m.add_argument("--forced-browse",  action="store_true", help="Gizli endpoint kəşfi")
    m.add_argument("--method-tamper",  action="store_true", help="Method-level authorization")
    m.add_argument("--jwt-attack",     action="store_true", help="JWT authorization bypass")

    scan = p.add_argument_group("Skan rejimi")
    scan.add_argument("--mode", default=ScanMode.ACTIVE,
                      choices=[ScanMode.SAFE, ScanMode.ACTIVE],
                      help="safe=GET-only | active=POST/PUT/DELETE (default: active)")

    n = p.add_argument_group("Şəbəkə")
    n.add_argument("--proxy",        default="",  help="HTTP proxy (Burp: http://127.0.0.1:8080)")
    n.add_argument("--scope",        default="",  help="Domain whitelist (target.com,api.target.com)")
    n.add_argument("--concurrency",  type=int,   default=20)
    n.add_argument("--delay",        type=float, default=0.15)
    n.add_argument("--timeout",      type=int,   default=12)
    n.add_argument("--retries",      type=int,   default=2)

    s = p.add_argument_group("Çıxış")
    s.add_argument("--wordlist",  default=None)
    s.add_argument("--threads",   type=int, default=10)
    s.add_argument("--verbose",   action="store_true")
    s.add_argument("--report",    action="store_true", help="HTML+JSON hesabat saxla")
    s.add_argument("--out",       default="reports")

    args = p.parse_args()

    if not any([args.all, args.idor, args.access_control, args.rbac,
                args.workflow, args.forced_browse, args.method_tamper, args.jwt_attack]):
        console.print("[yellow][~] Modul seçilmədi — --all ilə tam skan et.[/yellow]")
        p.print_help()
        sys.exit(0)

    try:
        findings, stats, root_causes = asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow][~] Dayandırıldı[/yellow]")
        findings, stats, root_causes = [], {}, []

    # Nəticə
    console.print(Rule("[bold]Skan Tamamlandı[/bold]"))
    print_terminal_summary(findings, args.url,
                           stats.get("elapsed_s", 0),
                           stats.get("requests", 0))
    print_root_causes(root_causes)
    print_stats(stats)

    if args.report or findings:
        html_p, json_p = save_reports(
            findings, args.url,
            stats.get("elapsed_s", 0),
            stats.get("requests", 0),
            args.out
        )
        console.print(f"[green][+] HTML → {html_p}[/green]")
        console.print(f"[green][+] JSON → {json_p}[/green]")

    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
