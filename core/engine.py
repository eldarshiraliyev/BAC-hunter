"""
BAC Hunter Engine — Authorization Intelligence Pipeline
======================================================

DISCOVER → MODEL → HYPOTHESIZE → TEST → VALIDATE → CORRELATE → REPORT

Bütün detektorları koordinasiya edir:
  1. Actor-ları müəyyənləşdir (token-dən)
  2. Ownership graph-ı qur
  3. SAFE/ACTIVE/CONTROLLED rejimlərini idarə et
  4. Detektorları pipeline-a ver
  5. FindingFingerprint ilə root-cause dedup
  6. Cavab: findings + root_cause_summary + stats
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.rule import Rule

from core.model import Actor, Resource, VulnClass
from core.ownership import OwnershipGraph, discover_ownership
from analysis.evidence import FindingFingerprint
from modules.http_client import AsyncClient, ScanConfig

console = Console()


# ── Rejim ─────────────────────────────────────────────────────────────────────

class ScanMode:
    """
    PASSIVE:    Heç bir aktiv sorğu göndərilmir — yalnız Burp trafiği analiz edilir.
    SAFE:       Yalnız GET/HEAD/OPTIONS — read-only, destruktiv deyil.
    ACTIVE:     POST/PUT/PATCH/DELETE — tam test, yalnız test account ilə.
    """
    PASSIVE    = "passive"
    SAFE       = "safe"
    ACTIVE     = "active"


# ── Scan nəticəsi ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    findings:          list[dict]  = field(default_factory=list)
    root_causes:       list[dict]  = field(default_factory=list)
    stats:             dict        = field(default_factory=dict)
    actor_low:         Optional[Actor] = None
    actor_high:        Optional[Actor] = None
    ownership_graph:   Optional[OwnershipGraph] = None


# ── Engine ────────────────────────────────────────────────────────────────────

class BACEngine:

    def __init__(self, url: str, cfg: ScanConfig, mode: str = ScanMode.ACTIVE):
        self.url   = url
        self.cfg   = cfg
        self.mode  = mode
        self._fp   = FindingFingerprint()

    async def run(self,
                  run_bola:      bool = True,
                  run_rbac:      bool = True,
                  run_workflow:  bool = True,
                  run_browse:    bool = True,
                  run_method:    bool = True,
                  run_jwt:       bool = True,
                  run_access:    bool = True,
                  ) -> ScanResult:

        result = ScanResult()
        start  = time.monotonic()

        async with AsyncClient(self.cfg) as client:

            # ── Step 1: Actor-ları müəyyənləşdir ──────────────────────────────
            actor_low  = Actor.from_token(self.cfg.low_token)
            actor_high = Actor.from_token(self.cfg.high_token) if self.cfg.high_token else Actor(identity="none")
            result.actor_low  = actor_low
            result.actor_high = actor_high

            console.print(
                f"[cyan][*] Actor (low):  {actor_low.identity} "
                f"| role={actor_low.role} | tenant={actor_low.tenant_id or '?'}[/cyan]"
            )
            if actor_high.identity != "none":
                console.print(
                    f"[cyan][*] Actor (high): {actor_high.identity} "
                    f"| role={actor_high.role}[/cyan]"
                )

            # ── Step 2: Ownership graph ────────────────────────────────────────
            graph = OwnershipGraph()
            if self.cfg.low_token and run_bola:
                console.print(Rule("[bold cyan]Ownership Discovery[/bold cyan]"))
                graph = await discover_ownership(
                    base_url      = self.url,
                    actor_low_id  = actor_low.identity,
                    actor_high_id = actor_high.identity,
                    low_hdrs      = self.cfg.build_headers(self.cfg.low_token),
                    high_hdrs     = (self.cfg.build_headers(self.cfg.high_token)
                                     if self.cfg.high_token else {}),
                    client        = client,
                    verbose       = self.cfg.verbose,
                )
            result.ownership_graph = graph

            # ── Step 3: Detektorlar ───────────────────────────────────────────

            all_raw: list[dict] = []

            # BOLA / IDOR
            if run_bola:
                console.print(Rule("[bold cyan]BOLA/IDOR Detection[/bold cyan]"))
                from detectors.bola import detect_bola
                r = await detect_bola(
                    self.url, client, self.cfg,
                    actor_low, actor_high, graph
                )
                all_raw.extend(r)
                console.print(f"[cyan][*] BOLA: {len(r)} ham tapıntı[/cyan]\n")

            # Access Control (18 kateqoriya)
            if run_access:
                console.print(Rule("[bold cyan]Access Control Matrix[/bold cyan]"))
                from modules.access_control import test_access_control
                r = await test_access_control(self.url, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] Access Control: {len(r)} ham tapıntı[/cyan]\n")

            # RBAC
            if run_rbac and self.cfg.low_token:
                console.print(Rule("[bold cyan]RBAC Bypass[/bold cyan]"))
                from modules.rbac_bypass import test_rbac_bypass
                r = await test_rbac_bypass(self.url, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] RBAC: {len(r)} ham tapıntı[/cyan]\n")

            # Workflow / Function / File auth
            if run_workflow:
                console.print(Rule("[bold cyan]Workflow & Function Auth[/bold cyan]"))
                from modules.workflow_auth import test_workflow_auth
                r = await test_workflow_auth(self.url, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] Workflow: {len(r)} ham tapıntı[/cyan]\n")

            # Forced Browse
            if run_browse:
                console.print(Rule("[bold cyan]Hidden Endpoint Discovery[/bold cyan]"))
                from urllib.parse import urlparse
                base = "{p.scheme}://{p.netloc}".format(p=urlparse(self.url))
                from modules.forced_browse import test_forced_browse
                r = await test_forced_browse(base, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] Forced browse: {len(r)} ham tapıntı[/cyan]\n")

            # Method Tampering
            if run_method:
                console.print(Rule("[bold cyan]Method-Level Authorization[/bold cyan]"))
                from modules.method_tamper import test_method_tampering
                r = await test_method_tampering(self.url, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] Method tamper: {len(r)} ham tapıntı[/cyan]\n")

            # JWT
            if run_jwt and self.cfg.jwt_token and self.cfg.jwt_token.startswith("eyJ"):
                console.print(Rule("[bold cyan]JWT Authorization[/bold cyan]"))
                from modules.jwt_manipulator import test_jwt
                r = await test_jwt(self.url, self.cfg.jwt_token, client, self.cfg)
                all_raw.extend(r)
                console.print(f"[cyan][*] JWT: {len(r)} ham tapıntı[/cyan]\n")

            req_count = client.total_requests

        # ── Step 4: Root-cause dedup + fingerprint ─────────────────────────────
        console.print(Rule("[bold]Korrelyasiya[/bold]"))
        final_findings = []
        for f in all_raw:
            if self._fp.add(f):
                final_findings.append(f)

        root_causes = self._fp.root_cause_summary()
        elapsed     = time.monotonic() - start

        console.print(
            f"[cyan][*] Ham tapıntı: {len(all_raw)} → "
            f"Root-cause dedup sonrası: {len(final_findings)} | "
            f"Root cause-lar: {len(root_causes)}[/cyan]"
        )

        result.findings    = final_findings
        result.root_causes = root_causes
        result.stats = {
            "total_raw":         len(all_raw),
            "total_findings":    len(final_findings),
            "root_causes":       len(root_causes),
            "requests":          req_count,
            "elapsed_s":         round(elapsed, 1),
            "fp_filtered":       len(all_raw) - len(final_findings),
            "fp_filter_rate":    (
                f"{(1 - len(final_findings)/max(len(all_raw),1))*100:.0f}%"
                if all_raw else "N/A"
            ),
            "objects_in_graph":  sum(
                len(v) for v in result.ownership_graph._graph.values()
            ) if result.ownership_graph else 0,
        }
        return result
