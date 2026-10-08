# vamp-waf-bypass

**WAF evasion tester — 15 bypass techniques for authorized security testing.**  
VampSecure Labs Security Research Division — pure Python, zero external dependencies.

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY.** Only use against systems you own or have explicit written permission to test.

## Features

- **15 bypass checks** (WAF-001–015) covering SQLi, XSS, path traversal, method override, IP spoofing, Log4Shell, rate limiting and more
- **Zero external dependencies** — uses only Python standard library (`urllib`, `re`, `json`…)
- **Pure check functions** for unit testing without network calls
- **JSON + HTML reports** for automated pipelines and human review
- **WAF fingerprinting** — detects Cloudflare, Incapsula, Sucuri, AWS WAF, Akamai, ModSecurity and more
- **Exit codes** CI-compatible: `2` = CRITICAL bypass, `1` = HIGH/MEDIUM, `0` = WAF blocking all

## Checks

| ID | Title | Severity | Category |
|----|-------|----------|----------|
| WAF-001 | WAF ausente o no detectado | high | Detección |
| WAF-002 | Bypass SQLi — codificación URL simple | critical | SQLi |
| WAF-003 | Bypass SQLi — doble codificación URL | critical | SQLi |
| WAF-004 | Bypass SQLi — comentarios inline | critical | SQLi |
| WAF-005 | Bypass XSS — HTML entities | critical | XSS |
| WAF-006 | Bypass XSS — variación de mayúsculas | high | XSS |
| WAF-007 | Bypass path traversal — codificado | critical | LFI/Path Traversal |
| WAF-008 | Bypass via X-HTTP-Method-Override | medium | HTTP Method Tampering |
| WAF-009 | Bypass via IP spoofing headers | high | Access Control |
| WAF-010 | Bypass via User-Agent whitelisting | medium | Evasión |
| WAF-011 | Bypass Log4Shell / JNDI | critical | RCE |
| WAF-012 | Bypass null byte injection | high | Evasión |
| WAF-013 | Bypass via fragmentación de parámetros | high | Evasión |
| WAF-014 | Sin protección contra rate limiting | medium | Rate Limiting |
| WAF-015 | Headers WAF revelados en respuesta | low | Information Disclosure |

## Installation

```bash
pip install vamp-waf-bypass
```

Or with Homebrew:

```bash
brew tap vampsecure-labs/labs
brew install vamp-waf-bypass
```

## Usage

```bash
# Basic scan
vamp-waf-bypass https://target.example.com

# Specify injection parameter
vamp-waf-bypass https://target.example.com --param search

# JSON report
vamp-waf-bypass https://target.example.com --json report.json

# HTML report
vamp-waf-bypass https://target.example.com --html report.html

# Filter by severity
vamp-waf-bypass https://target.example.com --severity critical high

# With case metadata
vamp-waf-bypass https://target.example.com --case CASO-2026-001 --analyst "Equipo Red"

# Quiet mode (exit code only, for CI)
vamp-waf-bypass https://target.example.com --quiet
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | WAF blocking all — no bypasses found |
| 1 | HIGH or MEDIUM bypasses detected |
| 2 | CRITICAL bypass confirmed |

## Sample Output

```
$ vamp-waf-bypass https://testapp.example.com --case CASO-2026-042 --analyst "Red Team VSS"

╭───────────────────────────────────────────────────────────────────╮
│  vamp-waf-bypass — WAF Evasion Tester · VampSecure Labs           │
│  Target  : https://testapp.example.com                            │
│  Case    : CASO-2026-042  · Analyst: Red Team VSS                 │
╰───────────────────────────────────────────────────────────────────╯

[+] WAF Fingerprinting...
    Detected : ModSecurity / OWASP CRS 3.3.4
    Headers  : X-Blocked-By: ModSecurity

╭─ CRITICAL — WAF-002 ────────────────────────────────────────────╮
│ SQLi bypass via URL single-encoding                               │
│ Payload : ?id=1%27%20OR%20%271%27%3D%271                         │
│ Response: HTTP 200 · Content-Type: text/html · 4.2 KB            │
│ Expected: HTTP 403 · BLOCKED                                      │
│ Evidence: Response body contains "syntax error near..."           │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WAF-003 ────────────────────────────────────────────╮
│ SQLi bypass via double URL-encoding                               │
│ Payload : ?id=1%2527%2520OR%2520%25271%2527%253D%25271           │
│ Response: HTTP 200 · 4.1 KB                                       │
│ Evidence: Database error message present in response body         │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WAF-009 ────────────────────────────────────────────────╮
│ IP spoofing via X-Forwarded-For: 10.0.0.1                        │
│ Response changed from HTTP 429 to HTTP 200                        │
│ Rate-limit bypass: WAF trusts client-supplied IP header           │
╰──────────────────────────────────────────────────────────────────╯

╭─ MEDIUM — WAF-014 ──────────────────────────────────────────────╮
│ No rate limiting on /login endpoint                               │
│ 50 requests in 3.2 s → all HTTP 200 · no throttling detected     │
╰──────────────────────────────────────────────────────────────────╯

╭─ LOW — WAF-015 ─────────────────────────────────────────────────╮
│ WAF product / version disclosed in response headers               │
│ Header: X-Powered-By: ModSecurity 2.9.7                          │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬──────────────────────────────────────────────────────┐
│ Severity │ Count                                                │
├──────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ 4                                                    │
│ HIGH     │ 3                                                    │
│ MEDIUM   │ 2                                                    │
│ LOW      │ 1                                                    │
│ PASS     │ 5                                                    │
└──────────┴──────────────────────────────────────────────────────┘
Exit code: 2 (CRITICAL bypass confirmed)
```

## Why vamp-waf-bypass vs. WAFNinja · GoTestWAF · w3af

| Feature | vamp-waf-bypass | WAFNinja | GoTestWAF | w3af |
|---------|:---------------:|:--------:|:---------:|:----:|
| Zero external dependencies (stdlib only) | ✅ | ❌ requests + sqlmap | ❌ Go runtime | ❌ large dep tree |
| WAF fingerprinting — 7 products | ✅ CF/AWS/Azure/ModSec/Nginx/F5/Incapsula | ⚠️ basic | ✅ | ⚠️ |
| Daemon / watch mode (`--watch N`) | ✅ | ❌ | ❌ | ❌ |
| CI/CD exit codes (0 / 1 / 2) | ✅ | ❌ | ✅ | ⚠️ |
| JSON + HTML dark-theme reports | ✅ | ❌ JSON only | ✅ | ⚠️ XML |
| OWASP WSTG-CONF-06 / MITRE ATT&CK T1036 aligned | ✅ | ❌ | ⚠️ partial | ⚠️ partial |
| Case + analyst metadata in report | ✅ | ❌ | ❌ | ❌ |
| Actively maintained (2024–2026) | ✅ | ❌ archived | ✅ | ⚠️ slow releases |

- **No dependencies**: `vamp-waf-bypass` uses only the Python standard library — no pip install, no virtualenv required. Drop it onto any analyst machine or CI runner and it works immediately.
- **Daemon mode**: `--watch N` re-runs the full check suite every N seconds, enabling continuous regression testing after WAF rule updates without scripting external loops.
- **Engagement metadata**: `--case` and `--analyst` fields propagate into JSON and HTML reports, satisfying chain-of-custody requirements for pentest deliverables.
- **Precision over noise**: each of the 15 checks has a dedicated pure function that can be unit-tested offline, ensuring reproducible results and avoiding false positives from network jitter.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| WAF-001 | WAF absent or not detectable on target | OWASP WSTG-CONF-06 | HIGH |
| WAF-002 | SQLi bypass via single URL encoding | OWASP WSTG-INPV-05 · MITRE T1036 | CRITICAL |
| WAF-003 | SQLi bypass via double URL encoding | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-004 | SQLi bypass via inline SQL comment injection | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-005 | XSS bypass via HTML entity encoding | OWASP WSTG-CLNT-01 | CRITICAL |
| WAF-006 | XSS bypass via mixed-case tag variation | OWASP WSTG-CLNT-01 | HIGH |
| WAF-007 | Path traversal bypass via percent-encoded sequences | OWASP WSTG-ATHZ-01 | CRITICAL |
| WAF-008 | HTTP method override via X-HTTP-Method-Override header | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-009 | Access control bypass via spoofed IP headers (X-Forwarded-For) | OWASP WSTG-IDNT-04 | HIGH |
| WAF-010 | WAF whitelist bypass via known-good User-Agent strings | MITRE T1036.005 | MEDIUM |
| WAF-011 | Log4Shell / JNDI injection payload not blocked (CVE-2021-44228) | NIST NVD · MITRE T1190 | CRITICAL |
| WAF-012 | Null byte injection evades pattern matching rules | OWASP WSTG-INPV-11 | HIGH |
| WAF-013 | Parameter fragmentation splits payload across multiple params | OWASP WSTG-INPV-01 | HIGH |
| WAF-014 | No rate limiting detected on sensitive endpoint | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-015 | WAF version / product name disclosed in response headers | OWASP WSTG-INFO-08 | LOW |

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
