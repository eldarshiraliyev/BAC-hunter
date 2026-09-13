"""
BAC Hunter v3 — Configuration
Real bug bounty analizinə görə yeniləndi (250 HackerOne report, 2017-2025)
"""

# ── Timeouts & Concurrency ────────────────────────────────────────────────────
DEFAULT_TIMEOUT      = 12
DEFAULT_CONCURRENCY  = 20
DEFAULT_DELAY        = 0.15
DEFAULT_RETRIES      = 2
RATE_LIMIT_SLEEP     = 2.0

# ── HTTP Methods ──────────────────────────────────────────────────────────────
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

# ── Status codes ──────────────────────────────────────────────────────────────
SUCCESS_CODES     = {200, 201, 204}
REDIRECT_CODES    = {301, 302, 303, 307, 308}
FORBIDDEN_CODES   = {401, 403}
INTERESTING_CODES = SUCCESS_CODES | REDIRECT_CODES

# ── User-Agent rotation ───────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile — bəzi zombie endpoint-lər yalnız mobile UA ilə açılır (Bykea pattern)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
]

DEFAULT_HEADERS = {
    "Accept":          "application/json, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control":   "no-cache",
    "Pragma":          "no-cache",
}

# ── IDOR ──────────────────────────────────────────────────────────────────────
IDOR_NUMERIC_RANGE  = 8
IDOR_MAX_CANDIDATES = 20
IDOR_COMMON_IDS     = ["1", "2", "3", "0", "100", "9999", "99999"]

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_WEAK_SECRETS = [
    "", "secret", "password", "123456", "admin", "test", "guest",
    "jwt_secret", "your-256-bit-secret", "changeme", "s3cr3t",
    "mysecretkey", "superSecret", "HS256", "key", "abc123",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
    "jwt", "token", "auth", "app_secret", "flask_secret",
    "django-insecure", "laravel_key", "rails_secret",
]

# JWT-də rol/icazə idarə edən field-lər (HackerOne report-larından)
JWT_ROLE_FIELDS = [
    "role", "roles", "user_role", "is_admin", "admin",
    "scope", "scopes", "groups", "permissions", "access_level",
    "privilege", "level", "type", "user_type", "account_type",
    "subscription", "plan", "tier",
]

JWT_ROLE_ESCALATION_VALUES = [
    {"role": "admin"}, {"role": "administrator"}, {"role": "superuser"},
    {"role": "root"}, {"role": "moderator"}, {"role": "staff"},
    {"is_admin": True}, {"admin": True}, {"admin": 1},
    {"scope": "admin"}, {"scope": "read:admin write:admin delete:*"},
    {"groups": ["admin", "superadmin"]},
    {"permissions": ["*"]}, {"permissions": ["admin:*"]},
    {"access_level": 9999}, {"access_level": "admin"},
    {"privilege": "root"}, {"user_type": "admin"},
    {"subscription": "enterprise"}, {"plan": "admin"},
]

# ── RBAC Bypass Headers ───────────────────────────────────────────────────────
BYPASS_HEADERS = {
    "X-Original-URL":            "{path}",
    "X-Rewrite-URL":             "{path}",
    "X-Forwarded-For":           "127.0.0.1",
    "X-Remote-IP":               "127.0.0.1",
    "X-Client-IP":               "127.0.0.1",
    "X-Real-IP":                 "127.0.0.1",
    "X-Host":                    "localhost",
    "X-Originating-IP":          "127.0.0.1",
    "Forwarded":                 "for=127.0.0.1;host=localhost",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-ProxyUser-Ip":            "127.0.0.1",
    "True-Client-IP":            "127.0.0.1",
    "CF-Connecting-IP":          "127.0.0.1",
    "X-Forwarded-Host":          "localhost",
    "X-Forwarded-Server":        "localhost",
    "X-HTTP-Host-Override":      "localhost",
}

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "_method",
]

# ── Path obfuscation ──────────────────────────────────────────────────────────
PATH_TRICKS = [
    "{path}/",
    "{path}//",
    "{path}?anything",
    "{path}#fragment",
    "{path}%09",
    "{path}%20",
    "{path};",
    "{path};.json",
    "{path}.css",
    "{path}.js",
    "{path}/..",
    "//{path}",
    "/{path}%2F",
    "/{path}%252F",
    "{path}..;/",
    "/%20{path}",
]

# ── Forced Browse built-in wordlist ───────────────────────────────────────────
BUILTIN_WORDLIST = [
    # Admin
    "admin", "admin/", "admin/dashboard", "admin/users", "admin/config",
    "admin/settings", "admin/panel", "admin/console", "admin/login",
    "administration", "administrator", "backend", "manage", "management",
    "panel", "controlpanel", "cp", "superadmin", "sysadmin",
    # API
    "api/admin", "api/v1/admin", "api/v2/admin", "api/v1/users",
    "api/internal", "api/private", "api/debug", "api/test",
    "api/v1/debug", "api/v1/config", "api/v1/health",
    # GraphQL (250 IDOR analizindən: sürətlə artır)
    "graphql", "graphiql", "api/graphql", "v1/graphql", "query", "gql",
    # Swagger/OpenAPI
    "swagger", "swagger-ui", "swagger-ui.html", "swagger/index.html",
    "api-docs", "api-docs/swagger.json", "openapi.json", "openapi.yaml",
    "v2/api-docs", "v3/api-docs",
    # Spring Boot Actuator
    "actuator", "actuator/health", "actuator/env",
    "actuator/beans", "actuator/mappings", "actuator/loggers",
    "actuator/metrics", "actuator/httptrace", "actuator/dump",
    # User management
    "users", "users/all", "accounts", "members",
    "user/1", "user/1/edit", "user/1/delete", "user/1/admin",
    # Sensitive files
    ".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
    ".git", ".git/config", ".git/HEAD",
    ".svn", ".svn/entries",
    "web.config", "app.config",
    "application.yml", "application.yaml", "application.properties",
    "config.yml", "config.yaml", "config.json",
    "docker-compose.yml", "dockerfile", ".dockerenv",
    # Backup
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db.sql", "dump.sql", "database.sql",
    # Debug
    "debug", "phpinfo.php", "info.php", "server-status", "server-info",
    # Logs
    "logs", "log", "error.log", "access.log", "debug.log",
    # Import/export (GitLab $20K pattern)
    "import", "export", "bulk", "batch",
    "api/v1/import", "api/v1/export",
    # Search endpoints (çox vaxt ACL-siz olur)
    "search", "api/search", "api/v1/search",
    # Webhook-lər
    "webhooks", "api/webhooks", "hooks",
    # Security
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    # Dev remnants
    "test", "dev", "staging", "internal", "private", "secret", "hidden",
]

# ── Report ────────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#FF3B30",
    "HIGH":     "#FF9500",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#30D158",
    "INFO":     "#0A84FF",
}

BANNER = r"""
 ____    _    ____   _   _             _
| __ )  / \  / ___| | | | |_   _ _ __ | |_ ___ _ __
|  _ \ / _ \| |     | |_| | | | | '_ \| __/ _ \ '__|
| |_) / ___ \ |___  |  _  | |_| | | | | ||  __/ |
|____/_/   \_\____| |_| |_|\__,_|_| |_|\__\___|_|

  OWASP Top 10 #1 — Broken Access Control Scanner  v3.0
  Authorization Intelligence Engine — 250+ HackerOne report analysis
"""
