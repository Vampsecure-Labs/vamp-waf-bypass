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

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
