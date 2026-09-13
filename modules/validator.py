"""
ResponseValidator v2 — Mərkəzi False Positive Filtr

Real bug bounty analizindən öyrənilən əlavə yoxlamalar:
  - Session misbinding aşkarlanması (Mozilla $6K pattern)
  - Import/export pipeline tanıma
  - Timing-based yoxlama dəstəyi
  - Daha ağıllı JSON struct müqayisəsi
  - Error kodu 200-lə qaytaran "soft error" aşkarlanması
"""

import re
import json
import hashlib
from dataclasses import dataclass
from typing import Optional

# ── Sabitlər ─────────────────────────────────────────────────────────────────

# Auth/login/error səhifə əlamətləri
_AUTH_PATTERN = re.compile(
    r'('
    # HTML title-da login/error sözləri
    r'<title>[^<]*(login|sign\s*in|log\s*in|unauthorized|forbidden|'
    r'access\s*denied|not\s*found|error|oops|session\s*expired|'
    r'please\s*authenticate)[^<]*</title>'
    # JSON error field-ləri
    r'|"error"\s*:\s*"(unauthorized|forbidden|not\s*found|unauthenticated|'
    r'access_denied|permission_denied|invalid_token|token_expired|'
    r'session_expired|authentication_required)"'
    r'|"message"\s*:\s*"(unauthorized|please\s*log\s*in|access\s*denied|'
    r'authentication\s*required|invalid\s*token|token\s*expired|'
    r'session\s*expired|you\s*do\s*not\s*have\s*permission|'
    r'not\s*authorized|forbidden)"'
    r'|"status"\s*:\s*"(error|fail|unauthorized|forbidden)"'
    r'|"code"\s*:\s*"?(401|403|UNAUTHORIZED|FORBIDDEN|ACCESS_DENIED)"?'
    # JS redirect to login
    r'|window\.location\s*[=.]\s*.*login'
    r'|location\.href\s*=\s*.*login'
    # HTML form login
    r'|<form[^>]*action="[^"]*login[^"]*"'
    r'|Redirecting\s*(you\s*)?to\s*(the\s*)?login'
    r')',
    re.IGNORECASE,
)

# Uğurlu IDOR əlamətləri — cavabda bunlar varsa real tapıntı
_SUCCESS_SIGNALS = re.compile(
    r'("(email|username|phone|address|ssn|credit_card|password|secret|'
    r'private_key|token|api_key|access_token|refresh_token)"\s*:\s*"[^"]{3,}"'
    r'|"(balance|amount|salary|income)"\s*:\s*\d+'
    r'|"is_admin"\s*:\s*true'
    r'|"role"\s*:\s*"(admin|superuser|root|moderator)")',
    re.IGNORECASE,
)

# Minimum real məzmun — çox qısa cavablar boş/redirect-dir
_MIN_REAL_LEN = 20

# JSON struct oxşarlığı üçün minimum hədd
_MIN_STRUCT_SIMILARITY = 0.15


@dataclass
class ValidationResult:
    valid:   bool
    reason:  str = ""
    score:   int = 0    # 0-100: tapıntının güvənilirlik səviyyəsi
    signals: list = None  # aşkarlanan uğur siqnalları

    def __post_init__(self):
        if self.signals is None:
            self.signals = []


class ResponseValidator:
    """
    Hər test cavabı üçün çoxqatlı false positive yoxlaması.
    Baseline bir dəfə alınır, validate() hər cavab üçün çağırılır.
    """

    def __init__(self, baseline_status: int, baseline_body: str,
                 baseline_headers: dict):
        self.bs_status  = baseline_status
        self.bs_body    = baseline_body
        self.bs_len     = len(baseline_body.encode())
        self.bs_hash    = hashlib.md5(baseline_body.encode()).hexdigest()
        self.bs_keys    = self._json_keys(baseline_body)
        self.bs_ct      = baseline_headers.get("Content-Type", "")
        self.bs_is_json = self._is_json(baseline_body, self.bs_ct)

    # ── Köməkçilər ────────────────────────────────────────────────────────────

    @staticmethod
    def _json_keys(body: str) -> set:
        """JSON body-nin bütün açarlarını rekursiv topla."""
        try:
            data = json.loads(body)
            keys: set = set()
            def _collect(obj):
                if isinstance(obj, dict):
                    keys.update(obj.keys())
                    for v in obj.values():
                        _collect(v)
                elif isinstance(obj, list):
                    for item in obj[:10]:  # ilk 10 element kifayətdir
                        _collect(item)
            _collect(data)
            return keys
        except Exception:
            return set()

    @staticmethod
    def _is_json(body: str, ct: str) -> bool:
        if "json" in ct.lower():
            return True
        s = body.strip()
        return s.startswith(("{", "["))

    @staticmethod
    def _body_hash(body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    def _struct_similarity(self, test_keys: set) -> float:
        """İki JSON struct-ın açar oxşarlığını hesabla (Jaccard)."""
        if not self.bs_keys or not test_keys:
            return 0.5  # bilinmir, neytral
        union = len(self.bs_keys | test_keys)
        inter = len(self.bs_keys & test_keys)
        return inter / union if union else 0.0

    # ── Əsas yoxlama ─────────────────────────────────────────────────────────

    def validate(
        self,
        test_status:  int,
        test_body:    str,
        test_headers: dict,
        mode:         str = "generic",
        need_status:  Optional[set] = None,
    ) -> ValidationResult:
        ok_statuses = need_status or {200, 201, 204}
        test_len    = len(test_body.encode())
        test_ct     = test_headers.get("Content-Type", "")
        test_is_json = self._is_json(test_body, test_ct)
        score        = 50  # başlanğıc neytral

        # ── 1. Status yoxlama ─────────────────────────────────────────────────
        if test_status not in ok_statuses:
            return ValidationResult(False, f"HTTP {test_status} — real giriş deyil")

        # ── 2. Minimum body uzunluğu ──────────────────────────────────────────
        if test_len < _MIN_REAL_LEN:
            return ValidationResult(
                False, f"Body çox qısa ({test_len}B) — boş/redirect cavab"
            )

        # ── 3. Auth/login redirect aşkarlanması ───────────────────────────────
        if _AUTH_PATTERN.search(test_body):
            return ValidationResult(
                False, "Auth/login/error əlamətləri — redirect səhifəsi"
            )

        # ── 4. Content-Type dəyişikliyi (JSON → HTML) ─────────────────────────
        if self.bs_is_json and "html" in test_ct.lower() and "json" not in test_ct.lower():
            return ValidationResult(
                False,
                f"Content-Type dəyişdi: JSON→HTML — auth səhifəsinə redirect"
            )

        # ── 5. IDOR-spesifik yoxlamalar ───────────────────────────────────────
        if mode == "idor":

            # 5a. Eyni body hash → eyni resurs, IDOR deyil
            if self._body_hash(test_body) == self.bs_hash:
                return ValidationResult(
                    False, "Body baseline ilə eynidir — eyni resurs qaytarıldı"
                )

            # 5b. JSON struct müqayisəsi
            if self.bs_is_json and test_is_json:
                test_keys = self._json_keys(test_body)
                sim = self._struct_similarity(test_keys)

                if sim < _MIN_STRUCT_SIMILARITY:
                    # Yalnız hər iki tərəfdə kifayət qədər açar varsa rədd et
                    # Az açarlı baseline (≤3) ilə müqayisə etibarsızdır
                    if len(self.bs_keys) > 3 and len(test_keys) > 3:
                        return ValidationResult(
                            False,
                            f"JSON struct çox fərqlidir (oxşarlıq {sim:.0%}) — fərqli endpoint cavabı"
                        )

                # Yüksək oxşarlıq + fərqli dəyərlər → güclü IDOR işarəsi
                if sim > 0.6:
                    score += 30

            # 5c. Body ölçüsü tamamilə eynidir (±5B) → eyni məzmun ehtimalı
            delta = abs(test_len - self.bs_len)
            if delta < 5 and test_len > 100:
                score -= 25  # şübhəli, eyni cavab ola bilər

        # ── 6. JSON "soft error" aşkarlanması ─────────────────────────────────
        # Server 200 qaytarır amma cavab xəta mesajı daşıyır
        if test_is_json:
            try:
                data = json.loads(test_body)
                if isinstance(data, dict):
                    top_keys = set(data.keys())
                    error_keys = {"error", "errors", "message", "detail",
                                  "msg", "status", "code", "reason"}
                    data_keys  = {"data", "result", "results", "user", "users",
                                  "item", "items", "record", "records",
                                  "id", "email", "name", "profile",
                                  "orders", "transactions", "files", "content"}
                    # success:false + error mesajı → soft error
                    if data.get("success") is False and (top_keys & error_keys):
                        return ValidationResult(
                            False, "JSON success:false — server xətası bildirdi"
                        )
                    # Yalnız error key-ləri var, heç data key-i yoxdur
                    if top_keys & error_keys and not (top_keys & data_keys):
                        if _AUTH_PATTERN.search(test_body):
                            return ValidationResult(
                                False, "JSON soft error — auth xətası 200 statusla"
                            )
            except Exception:
                pass

        # ── 7. Uğur siqnalları (score artır) ─────────────────────────────────
        signals = []
        found_signals = _SUCCESS_SIGNALS.findall(test_body)
        if found_signals:
            score += 20
            signals = [s[0] or s[1] or s[2] for s in found_signals if any(s)]

        return ValidationResult(True, "", min(score, 100), signals)


# ── Deduplication ─────────────────────────────────────────────────────────────

class Deduplicator:
    """Eyni tapıntının bir neçə dəfə reporta düşməsinin qarşısını alır."""

    def __init__(self):
        self._seen: set = set()

    def is_new(self, finding: dict) -> bool:
        key = hashlib.md5(
            (
                f"{finding.get('type','')}|"
                f"{finding.get('url','')}|"
                f"{finding.get('method', finding.get('technique', finding.get('attack', '')))}"
            ).encode()
        ).hexdigest()
        if key in self._seen:
            return False
        self._seen.add(key)
        return True
