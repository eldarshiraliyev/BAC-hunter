"""
Evidence & Confidence Engine
============================
"200 OK = IDOR" yanaşmasından uzaq.
Hər test üçün AUTHORIZATION VİOLATİON SÜBUTu yığır.

Confidence hesablanması:
  - Status əsaslı:          +20 (200 OK)
  - Ownership mismatch:     +35 (başqa actor-un object-i)
  - Tenant mismatch:        +30 (başqa tenant)
  - Sensitive field ifşası: +20 (email, role, api_key...)
  - Owner/actor mismatch:   +15
  - Body diff:              +10
  - Expected DENY idi:      +15
  Total max:                ~100

Əksinə azaldanlar:
  - Auth keyword body-də:   -50
  - success:false:          -40
  - JSON soft error:        -30
  - Body çox qısa:          -30
"""

from __future__ import annotations
import json
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from core.model import (
    Actor, Resource, ActionType, ExpectedPolicy,
    AuthorizationTest, VulnClass,
)


# ── Pattern-lər ────────────────────────────────────────────────────────────────

_AUTH_ERROR = re.compile(
    r'(<title>[^<]*(login|sign\s*in|unauthorized|forbidden|'
    r'access\s*denied|session\s*expired)[^<]*</title>'
    r'|"(error|message)"\s*:\s*"(unauthorized|forbidden|access.denied|'
    r'not.authorized|authentication.required|invalid.token)"'
    r'|"status"\s*:\s*"(error|fail|unauthorized)"'
    r'|window\.location.*login)',
    re.IGNORECASE,
)

_SENSITIVE = re.compile(
    r'"(email|phone|ssn|address|password|secret|api_key|access_token|'
    r'refresh_token|credit_card|bank_account|salary|role|permissions|'
    r'is_admin|internal_notes|private_key|recovery_code)"\s*:\s*"[^"]{2,}"',
    re.IGNORECASE,
)

_SUCCESS_STATUS = {200, 201, 204}


# ── Semantic JSON Comparison ──────────────────────────────────────────────────

def _flatten_json(body: str) -> dict:
    """JSON body-ni tam düz dict-ə çevir."""
    try:
        data = json.loads(body)
        result = {}
        def _walk(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (dict, list)):
                        _walk(v, full)
                    else:
                        result[k] = v   # key-i prefix-siz saxla — arama üçün
            elif isinstance(obj, list):
                for item in obj[:5]:
                    _walk(item, prefix)
        _walk(data)
        return result
    except Exception:
        return {}


def _extract_ids(flat: dict) -> dict:
    """Flat dict-dən ID sahələrini çıxar."""
    id_keys = re.compile(
        r'^(id|object_id|user_id|owner_id|account_id|'
        r'tenant_id|org_id|organization_id|creator_id)$',
        re.IGNORECASE,
    )
    return {k: str(v) for k, v in flat.items() if id_keys.match(k) and v}


# ── Evidence Engine ───────────────────────────────────────────────────────────

class EvidenceEngine:
    """
    Bir AuthorizationTest-i qiymətləndirir.
    Yalnız real authorization violation evidence-i olan hallarda
    is_finding=True qoyur.
    """

    def evaluate(self, test: AuthorizationTest,
                  baseline_body: str = "",
                  baseline_status: int = 0) -> AuthorizationTest:
        """
        test-i doldur: confidence, evidence, is_finding, vuln_class.
        """
        score   = 0
        evidence: dict = {}
        reasons: list  = []

        body    = test.observed_body
        status  = test.observed_status
        flat    = _flatten_json(body)
        ids     = _extract_ids(flat)

        # ── Tez rədd (confidence=0) ────────────────────────────────────────────
        if status not in _SUCCESS_STATUS:
            test.is_finding = False
            return test

        if len(body.encode()) < 20:
            test.is_finding = False
            return test

        if _AUTH_ERROR.search(body):
            test.is_finding = False
            return test

        # success:false
        try:
            d = json.loads(body)
            if isinstance(d, dict) and d.get("success") is False:
                test.is_finding = False
                return test
        except Exception:
            pass

        # ── Müsbət confidence siqnalları ──────────────────────────────────────

        # 1. Status uğurludur
        if status in _SUCCESS_STATUS:
            score += 20
            reasons.append(f"HTTP {status} — resurs qaytarıldı")

        # 2. Ownership mismatch — ən güclü siqnal
        actor_id = test.actor.identity
        owner_id = test.resource.owner_id or ids.get("owner_id", ids.get("user_id", ""))

        if owner_id and actor_id and owner_id != actor_id:
            score += 35
            evidence["ownership_mismatch"] = {
                "actor":  actor_id,
                "owner":  owner_id,
            }
            reasons.append(f"Ownership mismatch: actor={actor_id}, owner={owner_id}")

        # 3. Cross-tenant — ikinci güclü siqnal
        actor_tenant    = test.actor.tenant_id
        resource_tenant = test.resource.tenant_id or ids.get("tenant_id", ids.get("org_id", ""))

        if actor_tenant and resource_tenant and actor_tenant != resource_tenant:
            score += 30
            evidence["tenant_mismatch"] = {
                "actor_tenant":    actor_tenant,
                "resource_tenant": resource_tenant,
            }
            reasons.append(f"Tenant mismatch: {actor_tenant} → {resource_tenant}")

        # 4. Sensitive field ifşası
        sensitive_found = _SENSITIVE.findall(body)
        if sensitive_found:
            score += 20
            evidence["sensitive_fields"] = [m[0] for m in sensitive_found[:5]]
            reasons.append(f"Həssas field-lər ifşa olundu: {evidence['sensitive_fields']}")

        # 5. Object ID ownership ayrılığı
        # Cavabdakı ID test actor-unun ID-sindən fərqlidir
        resp_obj_id = ids.get("id") or ids.get("object_id") or ""
        req_obj_id  = test.resource.object_id
        if (resp_obj_id and req_obj_id and
                resp_obj_id == req_obj_id and
                owner_id and owner_id != actor_id):
            score += 15
            reasons.append(f"Başqa actor-un object-i ({req_obj_id}) qaytarıldı")

        # 6. Expected DENY idi, amma ALLOW gəldi
        if test.expected_policy == ExpectedPolicy.DENY:
            score += 15
            reasons.append("Expected: DENY, Observed: ALLOW")

        # 7. Baseline baseline ilə müqayisə
        if baseline_body and baseline_status == 200:
            # Eyni body → eyni resurs → IDOR deyil
            if hashlib.md5(body.encode()).hexdigest() == hashlib.md5(baseline_body.encode()):
                test.is_finding = False
                return test
            # Body fərqli → +10
            delta = abs(len(body.encode()) - len(baseline_body.encode()))
            if delta > 40:
                score += 10
                reasons.append(f"Body fərqi: Δ{delta}B")

        # ── Vuln class müəyyənləşdirmə ─────────────────────────────────────────
        vuln = _infer_vuln_class(test, evidence)

        # ── Minimum threshold ──────────────────────────────────────────────────
        # Yalnız ownership/tenant/sensitive field sübut varsa real finding say
        has_real_evidence = (
            "ownership_mismatch" in evidence or
            "tenant_mismatch"    in evidence or
            "sensitive_fields"   in evidence
        )
        if score < 30 or not has_real_evidence:
            test.is_finding = False
            return test

        # ── Finding! ──────────────────────────────────────────────────────────
        test.is_finding  = True
        test.confidence  = min(score, 100)
        test.evidence    = evidence
        test.vuln_class  = vuln
        test.reason      = " | ".join(reasons)
        return test


def _infer_vuln_class(test: AuthorizationTest, evidence: dict) -> VulnClass:
    """Evidence-ə əsasən ən uyğun vuln class seç."""
    if "tenant_mismatch" in evidence:
        return VulnClass.CROSS_TENANT

    method = test.method.upper()
    action = test.action

    if action == ActionType.DELETE or method == "DELETE":
        return VulnClass.DELETE_IDOR
    if action == ActionType.WRITE or method in {"PUT", "PATCH"}:
        return VulnClass.WRITE_IDOR
    if action == ActionType.EXEC:
        return VulnClass.BFLA

    if "ownership_mismatch" in evidence:
        actor = test.actor
        if actor.is_admin():
            return VulnClass.BFLA
        return VulnClass.BOLA

    if "sensitive_fields" in evidence:
        return VulnClass.BOPLA

    return VulnClass.BOLA


# ── Fingerprint & Root-Cause Dedup ───────────────────────────────────────────

class FindingFingerprint:
    """
    MD5(url) əvəzinə semantic fingerprint:
    method + normalized_endpoint + vuln_class + action + ownership_context

    Məqsəd: eyni root cause-dan gələn 50 tapıntını 1-ə endirmək.
    """

    def __init__(self):
        self._seen: dict[str, list[dict]] = {}   # fingerprint → findings
        self._root_causes: list[dict] = []

    @staticmethod
    def _normalize_endpoint(url: str) -> str:
        """ID-ləri {id} ilə əvəz et — eyni endpoint structure aşkarla."""
        import re
        from urllib.parse import urlparse
        path = urlparse(url).path
        path = re.sub(r'/\d+', '/{id}', path)
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}', path
        )
        return path

    def add(self, finding: dict) -> bool:
        """
        True qaytar → yeni root cause (reporta düş).
        False → artıq görülmüş root cause (skip).
        """
        norm_ep    = self._normalize_endpoint(finding.get("url", ""))
        vuln_class = finding.get("type", "")
        method     = finding.get("method", "GET")
        action     = finding.get("action", "")
        tenant_ctx = (finding.get("resource") or {}).get("tenant_id", "")

        # Root cause key
        rc_key = hashlib.md5(
            f"{method}|{norm_ep}|{vuln_class}|{action}|{tenant_ctx}".encode()
        ).hexdigest()

        if rc_key not in self._seen:
            self._seen[rc_key] = []
            self._root_causes.append({
                "root_cause":     rc_key[:8],
                "vuln_class":     vuln_class,
                "normalized_url": norm_ep,
                "method":         method,
                "count":          0,
                "examples":       [],
            })

        self._seen[rc_key].append(finding)
        rc = next(r for r in self._root_causes if r["root_cause"] == rc_key[:8])
        rc["count"] += 1
        if len(rc["examples"]) < 3:
            rc["examples"].append(finding.get("url", ""))

        # İlk tapıntı → reporta düş; sonrakılar eyni root cause
        return len(self._seen[rc_key]) == 1

    def root_cause_summary(self) -> list[dict]:
        return sorted(self._root_causes, key=lambda x: -x["count"])
