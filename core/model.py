"""
Authorization Model — BAC Hunter-in ürəyi

Actor → Resource → Action matrisi.
Bütün detektorlar bu model üzərindən işləyir — heç bir detektor
birbaşa "200 = vulnerable" qərarı vermir.

OWASP BOLA/BFLA/BOPLA testinin mahiyyəti:
  "Bu identity bu konkret object üzərində bu action-u edə bilərmi?"
"""

from __future__ import annotations
import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enum-lər ─────────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    READ   = "READ"
    WRITE  = "WRITE"
    DELETE = "DELETE"
    EXEC   = "EXEC"     # function execution
    BULK   = "BULK"     # bulk/list access

class ExpectedPolicy(str, Enum):
    ALLOW = "ALLOW"
    DENY  = "DENY"
    UNKNOWN = "UNKNOWN"

class VulnClass(str, Enum):
    BOLA          = "BOLA/Horizontal IDOR"
    BFLA          = "BFLA/Vertical PrivEsc"
    BOPLA         = "BOPLA/Property Exposure"
    CROSS_TENANT  = "Cross-Tenant Access"
    WRITE_IDOR    = "Write/Update IDOR"
    DELETE_IDOR   = "Delete IDOR"
    ROLE_BYPASS   = "Role/Permission Bypass"
    METHOD_AUTH   = "Method-Level Authorization"
    FUNC_AUTH     = "Unauthorized Function Execution"
    WORKFLOW      = "Workflow/State Auth Bypass"
    GRAPHQL_AUTH  = "GraphQL Authorization"
    BULK_AUTH     = "Bulk Authorization"
    UNAUTH        = "Unauthenticated Bypass"
    HIDDEN_EP     = "Hidden Endpoint Access"
    FILE_AUTH     = "File/Object Authorization"
    JWT_BYPASS    = "JWT Authorization Bypass"
    API_VERSION   = "API Version Authorization"
    MASS_ASSIGN   = "Mass Assignment"


# ── Actor ─────────────────────────────────────────────────────────────────────

@dataclass
class Actor:
    """Kimin adından sorğu gedir."""
    identity:  str            # user_A, token hash, "anonymous"
    role:      str = "unknown"
    tenant_id: str = ""
    token:     str = ""       # raw token

    @classmethod
    def from_token(cls, token: str) -> "Actor":
        if not token:
            return cls(identity="anonymous", role="anonymous")
        # JWT-dən məlumat çıxar
        try:
            import base64, json as _j
            parts = token.split(".")
            if len(parts) == 3:
                pad = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = _j.loads(base64.urlsafe_b64decode(pad))
                identity  = str(payload.get("sub") or payload.get("user_id") or
                                payload.get("id") or payload.get("uid") or "unknown")
                role      = str(payload.get("role") or payload.get("roles") or
                                payload.get("user_type") or "user")
                tenant_id = str(payload.get("tenant_id") or payload.get("org_id") or
                                payload.get("organization_id") or "")
                return cls(identity=identity, role=role,
                           tenant_id=tenant_id, token=token)
        except Exception:
            pass
        # Cookie/session — hash ilə identifikasiya
        return cls(identity=hashlib.md5(token.encode()).hexdigest()[:8],
                   role="session", token=token)

    def is_admin(self) -> bool:
        return self.role.lower() in {"admin", "administrator", "superuser", "root", "staff"}

    def is_anonymous(self) -> bool:
        return self.identity == "anonymous"


# ── Resource ──────────────────────────────────────────────────────────────────

@dataclass
class Resource:
    """Hansı obyektə müraciət edilir."""
    url:         str
    object_type: str = ""     # "user", "invoice", "order" ...
    object_id:   str = ""     # "123", "uuid-..."
    owner_id:    str = ""     # cavabdan çıxarılır
    tenant_id:   str = ""     # cavabdan çıxarılır
    properties:  dict = field(default_factory=dict)  # açıq property-lər

    @classmethod
    def from_url(cls, url: str) -> "Resource":
        from urllib.parse import urlparse
        import re
        parsed = urlparse(url)
        path   = parsed.path

        # Object type: /api/v1/ORDERS/123 → "orders"
        parts = [p for p in path.split("/") if p and not p.startswith("v")]
        obj_type = parts[-2] if len(parts) >= 2 else parts[-1] if parts else ""

        # Object ID
        id_match = re.search(
            r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|'
            r'\d{1,15})(?:/|$)', path
        )
        obj_id = id_match.group(1) if id_match else ""

        return cls(url=url, object_type=obj_type.rstrip("s").lower(),
                   object_id=obj_id)

    def extract_from_response(self, body: str):
        """Cavab body-sindən owner/tenant/property məlumatı çıxar."""
        try:
            data = json.loads(body)
            flat = self._flatten(data)

            # Owner field-lərini tap
            for k in ["owner_id", "user_id", "creator_id", "created_by",
                      "author_id", "account_id", "member_id"]:
                if k in flat:
                    self.owner_id = str(flat[k])
                    break

            # Tenant field-lərini tap
            for k in ["tenant_id", "org_id", "organization_id",
                      "workspace_id", "company_id", "team_id"]:
                if k in flat:
                    self.tenant_id = str(flat[k])
                    break

            # Həssas property-ləri qeyd et
            sensitive = {"email", "phone", "ssn", "address", "password",
                         "secret", "api_key", "access_token", "credit_card",
                         "bank_account", "salary", "role", "permissions",
                         "is_admin", "internal_notes", "private_key"}
            self.properties = {k: v for k, v in flat.items() if k in sensitive}
        except Exception:
            pass

    @staticmethod
    def _flatten(obj, prefix="", result=None):
        if result is None:
            result = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    Resource._flatten(v, full_key, result)
                else:
                    result[k] = v  # son key — prefix olmadan
        elif isinstance(obj, list) and obj:
            Resource._flatten(obj[0], prefix, result)
        return result


# ── AuthorizationTest ─────────────────────────────────────────────────────────

@dataclass
class AuthorizationTest:
    """Bir authorization testi üçün tam kontekst."""
    actor:           Actor
    resource:        Resource
    action:          ActionType
    method:          str
    expected_policy: ExpectedPolicy = ExpectedPolicy.UNKNOWN

    # Cavabdan doldurulur
    observed_status: int  = 0
    observed_body:   str  = ""
    observed_headers: dict = field(default_factory=dict)
    elapsed:         float = 0.0

    # Analiz nəticəsi
    vuln_class:      Optional[VulnClass] = None
    confidence:      int = 0         # 0-100
    evidence:        dict = field(default_factory=dict)
    is_finding:      bool = False
    reason:          str  = ""

    def to_finding(self) -> Optional[dict]:
        if not self.is_finding:
            return None
        sev = ("CRITICAL" if self.confidence >= 85
               else "HIGH"   if self.confidence >= 65
               else "MEDIUM" if self.confidence >= 45
               else "LOW")
        return {
            "type":       self.vuln_class.value if self.vuln_class else "Authorization Flaw",
            "severity":   sev,
            "confidence": self.confidence,
            "url":        self.resource.url,
            "method":     self.method,
            "actor": {
                "identity":  self.actor.identity,
                "role":      self.actor.role,
                "tenant_id": self.actor.tenant_id,
            },
            "resource": {
                "type":      self.resource.object_type,
                "id":        self.resource.object_id,
                "owner_id":  self.resource.owner_id,
                "tenant_id": self.resource.tenant_id,
            },
            "action":          self.action.value,
            "expected_policy": self.expected_policy.value,
            "status":          self.observed_status,
            "evidence":        self.evidence,
            "reason":          self.reason,
            "snippet":         self.observed_body[:500],
        }
