<div align="center">

# BACHunter

**Authorization Intelligence Engine for Broken Access Control**

*Bug Bounty Edition — v3.0*

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20%231-red?style=flat-square)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=flat-square)](https://hackerone.com)

</div>

---

> **BACHunter is not just another IDOR scanner.**
> It is an authorization intelligence engine that attempts to *prove* that an actor performed an action on a resource they should not be authorized to access — with a confidence score, ownership context, and root-cause correlation.

```
WHO    →  user_A  (role: user, tenant: A)
WHAT   →  invoice #456  (owner: user_B, tenant: B)
ACTION →  READ
EXPECT →  DENY
ACTUAL →  ALLOW  (HTTP 200, owner_id mismatch detected)
CONF   →  96%   →  BOLA/Horizontal IDOR
```

---

## Table of Contents

- [Why BACHunter](#why-bachunter)
- [Coverage](#coverage)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [How It Works](#how-it-works)
- [Output](#output)
- [Responsible Use](#responsible-use)
- [Legal Notice](#legal-notice)

---

## Why BACHunter

Most access control scanners work like this:

```
mutate ID  →  send request  →  got 200?  →  flag it
```

This produces massive false positives. A 200 response does not mean
unauthorized access occurred — it could be a login redirect, a soft error,
or simply the same resource returned under a different URL.

BACHunter works differently:

```
Traffic → Endpoint Discovery → Identity Discovery → Object Discovery
       → Ownership Mapping → Authorization Model Inference
       → Actor × Resource × Action Matrix → Differential Testing
       → Semantic Response Analysis → Side-effect Verification
       → Impact Analysis → Root-cause Correlation → Confidence Score
       → PoC → Report
```

A finding is only raised when **authorization violation evidence** is present:
- Ownership mismatch (actor ≠ resource owner)
- Tenant mismatch (cross-tenant data access)
- Sensitive field exposure (email, api_key, role, permissions...)

---

## Coverage

BACHunter covers **20 Broken Access Control categories**:

### A — Object Authorization (BOLA)
| Category | Description |
|----------|-------------|
| Horizontal IDOR / BOLA | Access another user's object at the same privilege level |
| Read-only IDOR | Unauthorized read of another actor's resource |
| Write / Update IDOR | Unauthorized modification via PUT/PATCH |
| Delete IDOR | Unauthorized deletion via DELETE |
| BOPLA | Broken Object Property Level — sensitive fields exposed to unauthorized actors |
| Bulk Authorization | Unrestricted list endpoints returning all objects |

### B — Function Authorization (BFLA)
| Category | Description |
|----------|-------------|
| Vertical Privilege Escalation | Low-privilege actor accessing admin functions |
| Role / Permission Bypass | Header injection to impersonate higher roles |
| Unauthorized Function Execution | Direct invocation of admin actions (approve, delete, ban...) |
| Method-Level Authorization | GET protected but PUT/DELETE not |

### C — API Authorization
| Category | Description |
|----------|-------------|
| REST API Authorization Flaws | Per-method ACL gaps across 18 common endpoints |
| GraphQL Authorization | Mutation/query ownership checks, introspection exposure |
| API Version Authorization | Older API versions missing updated authorization logic |
| HTTP Method Tampering | Method override headers, TRACE, destructive method access |

### D — Workflow & Context
| Category | Description |
|----------|-------------|
| Multi-step / Workflow Auth Bypass | Skipping required state transitions in checkout, approval flows |
| Cross-Tenant Access | Accessing another organization's data in multi-tenant systems |
| File / Object Authorization | Unauthorized file download, path traversal, attachment access |
| Hidden Endpoint Access | Admin panels, debug routes, internal APIs |
| Unauthenticated Authorization Bypass | Endpoints accessible without any credentials |
| Mass Assignment | Injecting privileged fields (is_admin, role) via request body |

---

## Architecture

```
BACHunter/
│
├── core/
│   ├── engine.py          # Pipeline orchestrator: DISCOVER→MODEL→TEST→REPORT
│   ├── model.py           # Actor / Resource / Action / AuthorizationTest
│   └── ownership.py       # Ownership graph discovery and cross-access mapping
│
├── analysis/
│   └── evidence.py        # EvidenceEngine + FindingFingerprint (root-cause dedup)
│
├── detectors/
│   └── bola.py            # BOLA/IDOR with ownership-graph-aware testing
│
├── modules/
│   ├── http_client.py     # Async aiohttp engine (retry, proxy, UA rotation, scope)
│   ├── access_control.py  # Universal access control — 20 categories
│   ├── rbac_bypass.py     # RBAC bypass — 20+ techniques
│   ├── workflow_auth.py   # Workflow / function / file authorization
│   ├── forced_browse.py   # Hidden endpoint discovery (48k wordlist, soft-404 aware)
│   ├── method_tamper.py   # Method-level authorization
│   ├── jwt_manipulator.py # JWT authorization bypass
│   ├── validator.py       # Central false-positive filter (6-layer)
│   └── reporter.py        # Terminal table + HTML dashboard + JSON export
│
├── wordlists/
│   ├── bac-hunter-combined.txt   # 48,420 entries (SecLists + custom high-priority)
│   └── bac-hunter-quick.txt      # 109 critical paths for fast recon
│
└── main.py                # CLI entry point
```

### Authorization Model

Every request is modeled as:

```python
Actor(identity="user_A", role="user", tenant_id="tenant_A")
    +
Resource(object_id="456", owner_id="user_B", tenant_id="tenant_B")
    +
Action(READ / WRITE / DELETE / EXEC)
    →
EvidenceEngine → confidence=96% → BOLA/Horizontal IDOR
```

### Ownership Graph

BACHunter discovers what objects each actor owns, then performs
**ownership-aware cross-access tests** — not blind ID increments:

```
Actor A owns:  [invoice_101, order_201, file_301]
Actor B owns:  [invoice_102, order_202, file_302]

Test: Actor A → invoice_102  →  Expected: DENY
Test: Actor B → invoice_101  →  Expected: DENY
```

### EvidenceEngine — Confidence Scoring

A finding is only created when real authorization violation evidence exists.

**Positive signals (raise confidence):**

| Signal | Points |
|--------|--------|
| HTTP 200/201/204 returned | +20 |
| Ownership mismatch (actor ≠ owner) | +35 |
| Tenant mismatch (cross-tenant) | +30 |
| Sensitive field exposure | +20 |
| Expected DENY, observed ALLOW | +15 |
| Body delta from baseline | +10 |

**Negative signals (suppress finding):**

| Signal | Points |
|--------|--------|
| Auth/login keyword in body | −50 |
| `success: false` in JSON | −40 |
| Content-Type switched to HTML | −30 |

**Threshold:** A finding is raised only when `score ≥ 30` **AND** at least one of
`ownership_mismatch`, `tenant_mismatch`, or `sensitive_fields` is present in evidence.
The threshold of 30 was chosen to require at least one real authorization signal
(+35 or +30) in addition to a successful HTTP status (+20) — a 200 alone is never enough.

### Root-Cause Deduplication

Instead of MD5-hashing raw URLs, BACHunter uses semantic fingerprinting
(normalized endpoint + method + vuln class):

```
/api/users/123  ┐
/api/users/456  ├──  normalized: /api/users/{id}  →  1 root cause, count=3
/api/users/789  ┘
```

50 raw anomalies may map to 1 root cause with affected endpoints listed —
which is what a bug bounty report actually needs.

---

## Installation

```bash
git clone https://github.com/eldarshiraliyev/BAC-hunter
cd BAC-hunter
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, aiohttp ≥3.9, rich ≥13.7, PyJWT ≥2.8, aiofiles ≥23.2

---

## Usage

```bash
# Full scan — all 20 categories
python main.py --url https://target.com/api/users/42 \
  --token eyJ_user... \
  --admin-token eyJ_admin... \
  --all --report

# BOLA/IDOR only (read + write + delete + BOPLA)
python main.py --url https://target.com/api/orders/123 \
  --token eyJ... --idor

# Safe mode — read-only, no destructive requests
python main.py --url https://target.com/api/users/42 \
  --token eyJ... --all --mode safe

# Through Burp Suite proxy
python main.py --url https://target.com/api/users/42 \
  --token eyJ... --all \
  --proxy http://127.0.0.1:8080

# Scope-restricted (bug bounty programs)
python main.py --url https://api.target.com/v1/users/5 \
  --token eyJ... --all \
  --scope api.target.com,target.com --report

# Gentle rate limiting for sensitive targets
python main.py --url https://target.com/api/users/42 \
  --token eyJ... --all \
  --concurrency 5 --delay 0.5

# Forced browsing with custom wordlist
python main.py --url https://target.com \
  --token eyJ... --forced-browse \
  --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```

### All Options

```
Target:
  --url             Target URL (required)
  --token           Low-privilege auth token (Bearer JWT or Cookie string)
  --admin-token     High-privilege token (for ownership-aware differential testing).
                    Without this, RBAC and vertical PrivEsc tests are limited
                    to header injection and path tricks only.
  --jwt             JWT token specifically for the JWT module.
                    If omitted, --token is used for JWT tests as well.
  -H 'K: V'         Extra header (repeatable)

Modules:
  --all             Run all modules
  --idor            BOLA/IDOR — read, write, delete, BOPLA
  --access-control  Universal access control — 20 categories
  --rbac            RBAC bypass — 20+ techniques
  --workflow        Workflow / function / file authorization
  --forced-browse   Hidden endpoint discovery
  --method-tamper   Method-level authorization
  --jwt-attack      JWT authorization bypass

Scan mode:
  --mode safe       GET/HEAD/OPTIONS only — no destructive requests.
                    Use this when you are unsure about scope or do not
                    have a dedicated test account.
  --mode active     Full testing including POST/PUT/DELETE (default).
                    A warning is printed at startup. Use only with a
                    test account on an authorized target.

Network:
  --proxy URL       HTTP proxy (Burp Suite: http://127.0.0.1:8080)
  --scope DOMAINS   Comma-separated allowed domains. Redirect chains
                    that leave this scope are blocked. Omitting this
                    flag means no domain restriction is enforced.
  --concurrency N   Async semaphore limit (default: 20).
                    Lower to 5 for sensitive targets with rate limits.
  --delay SEC       Delay between requests (default: 0.15s).
                    Raise to 0.5 for conservative scanning.
  --timeout SEC     Per-request timeout (default: 12)
  --retries N       Retry count on network error (default: 2)

Output:
  --wordlist PATH   Custom wordlist for forced browsing.
                    Note: built-in wordlist includes paths like .env,
                    .git/config, db.sql — some programs consider these
                    out of scope. Check program rules before running.
  --verbose         Show every request and filter reason
  --report          Save HTML + JSON reports (auto-saves when findings exist)
  --out DIR         Report output directory (default: reports/)
```

---

## Scan Modes

| Mode | Methods Used | Use Case |
|------|-------------|----------|
| `--mode safe` | GET, HEAD, OPTIONS | Recon, scope validation, passive enumeration |
| `--mode active` | All HTTP methods | Full bug bounty testing with test accounts |

> **Always use `--mode safe` when:**
> - You are not yet sure about the target's full scope
> - You do not have a dedicated test account
> - The program rules prohibit automated scanning

> **Default concurrency (20) and delay (0.15s) may trigger rate limits.**
> For most bug bounty targets use `--concurrency 5 --delay 0.5`.

---

## How It Works

### 1. Actor Discovery
Tokens are parsed (JWT or session) to extract identity, role, and tenant context before any request is sent.

### 2. Ownership Graph
BACHunter queries list endpoints to discover which objects belong to which actor. Cross-ownership tests are then targeted — not random ID increments.

### 3. Authorization Matrix
Every test is structured as `Actor × Resource × Action`. The expected policy (ALLOW/DENY) is inferred from ownership context.

### 4. Differential Testing
The same resource is accessed with different actor contexts. Response bodies are compared at the semantic level — not just status codes.

### 5. Evidence Engine
Each response is evaluated for authorization violation evidence. Six negative signals can suppress a finding regardless of HTTP status. A 200 alone is never enough to raise a finding.

### 6. Root-Cause Correlation
Findings sharing the same normalized endpoint, method, and vulnerability class are merged into a single root cause with an affected count — reducing noise in the final report.

---

## Output

### Terminal

```
╭────────────┬──────────────────────────┬────────────────────────────────────────┬────────╮
│ Sev        │ Type                     │ URL                                    │ Status │
├────────────┼──────────────────────────┼────────────────────────────────────────┼────────┤
│ CRITICAL   │ BOLA/Horizontal IDOR     │ https://target.com/api/invoices/456    │ 200    │
│ CRITICAL   │ Cross-Tenant Access      │ https://target.com/api/orders/102      │ 200    │
│ HIGH       │ BOPLA/Property Exposure  │ https://target.com/api/users/1         │ 200    │
│ HIGH       │ Role/Permission Bypass   │ https://target.com/api/admin           │ 200    │
╰────────────┴──────────────────────────┴────────────────────────────────────────┴────────╯

Summary: 4 findings | CRIT 2 | HIGH 2 | MED 0 | LOW 0
Requests: 1,247 | Elapsed: 38.4s | FP filter: 94%

Root Cause Analysis:
  3c729afc  BOLA/Horizontal IDOR  /api/invoices/{id}  affected: 12
  a1b2c3d4  Cross-Tenant Access   /api/orders/{id}    affected:  8
```

### HTML Report
Interactive dashboard with severity filters, search, bar chart by finding type,
collapsible response snippets, copy-URL button, and in-browser JSON export.

### JSON Report
Structured output with full actor/resource/action context, confidence score,
evidence fields, and root-cause grouping — ready for automated pipelines.

---

## Recommended Workflow

```bash
# 1. Recon — safe mode, no destructive requests
python main.py --url https://target.com \
  --token eyJ... --all --mode safe \
  --concurrency 5 --delay 0.5 --report

# 2. Review HTML report, identify interesting endpoints

# 3. Targeted active test on specific endpoint
python main.py --url https://target.com/api/invoices/123 \
  --token eyJ_user... --admin-token eyJ_admin... \
  --idor --rbac --mode active --verbose --report

# 4. Pipe through Burp for manual review
python main.py --url https://target.com/api/invoices/123 \
  --token eyJ... --all --proxy http://127.0.0.1:8080
```

---

## Responsible Use

**Before running any scan:**

1. Confirm the target is within the program's defined scope
2. Use `--scope target.com` to prevent accidental out-of-scope requests
3. Use `--mode safe` for initial recon
4. Use dedicated test accounts — never scan against real user data
5. Check program rules on automated scanning and rate limits
6. Set `--concurrency 5 --delay 0.5` for conservative scanning

**Note on built-in wordlist:** The wordlist includes paths such as `.env`,
`.git/config`, and `db.sql`. Accessing these paths may be considered
out-of-scope on some programs. Review the program policy before running
`--forced-browse`.

---

## Legal Notice

**This tool is intended for authorized security testing only.**

Use only on:
- Bug bounty programs within their defined scope
- CTF / lab environments
- Systems you own or have explicit written permission to test

Unauthorized use is illegal and unethical.

---

## Author

Built by **Eldar Shiraliyev** — Cybersecurity Portfolio

*Demonstrating practical knowledge of OWASP Top 10 #1 — Broken Access Control
through real-world authorization intelligence tooling.*