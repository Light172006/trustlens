"""
TrustLens Web Security Analyzer - Comprehensive Analyzer Engine Test Suite (Phase 11)
Verifies URL validation, SSRF guard protections, deterministic security rules,
ML posture prediction, confidence abstention, risk aggregation invariants, and full engine synthesis.
"""

import asyncio
import ipaddress
from pathlib import Path
import sys
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "analyzer"))
sys.path.insert(0, str(BASE_DIR / "training"))

from url_validator import URLValidationError, normalize_target_url
from ssrf_guard import (
    SSRFSecurityException,
    is_ip_address,
    is_restricted_ip,
    parse_ip_literal,
    resolve_and_validate_destination,
    validate_hostname_ssrf,
)
from security_rules import evaluate_security_findings
from ml_predictor import MLSecurityPosturePredictor
from risk_aggregator import RiskAggregator
from engine import WebSecurityAnalyzer
from models import WebSecurityReport


# ==========================================
# 1. URL Validator & Normalizer Tests
# ==========================================

def test_url_validator_valid_https():
    res = normalize_target_url("https://example.com")
    assert res["scheme"] == "https"
    assert res["hostname"] == "example.com"
    assert res["port"] == 443
    assert res["registrable_domain"] == "example.com"
    assert res["normalized_url"] == "https://example.com/"


def test_url_validator_valid_http():
    res = normalize_target_url("http://example.org:8080/test")
    assert res["scheme"] == "http"
    assert res["hostname"] == "example.org"
    assert res["port"] == 8080
    assert res["path"] == "/test"


def test_url_validator_default_scheme():
    res = normalize_target_url("github.com")
    assert res["scheme"] == "https"
    assert res["hostname"] == "github.com"
    assert res["normalized_url"] == "https://github.com/"


def test_url_validator_idn_punycode():
    res = normalize_target_url("https://münchen.de")
    assert res["hostname"] == "xn--mnchen-3ya.de"
    assert res["is_idn"] is True


def test_url_validator_public_suffix_extraction():
    res = normalize_target_url("https://sub.news.bbc.co.uk/stories")
    assert res["registrable_domain"] == "bbc.co.uk"


def test_url_validator_reject_unsupported_schemes():
    for bad_scheme in ["ftp://example.com", "file:///etc/passwd", "gopher://example.com", "ws://example.com"]:
        with pytest.raises(URLValidationError, match="Unsupported URL scheme"):
            normalize_target_url(bad_scheme)


def test_url_validator_reject_unpermitted_ports():
    for bad_port in ["https://example.com:22", "https://example.com:3306", "https://example.com:6379", "http://example.com:25"]:
        with pytest.raises(URLValidationError, match="not in permitted web ports"):
            normalize_target_url(bad_port)


def test_url_validator_reject_credentials_in_url():
    with pytest.raises(URLValidationError, match="Credentials in URL"):
        normalize_target_url("https://admin:secret@example.com/")


def test_url_validator_reject_empty_or_malformed():
    with pytest.raises(URLValidationError):
        normalize_target_url("")
    with pytest.raises(URLValidationError):
        normalize_target_url("   ")


# ==========================================
# 2. SSRF Guard Tests
# ==========================================

def test_ssrf_detects_all_loopback_variants():
    loopbacks = [
        "127.0.0.1",
        "127.0.0.2",
        "127.1.2.3",
        "localhost",
        "localhost.localdomain",
        "::1",
        "0.0.0.0",
        "2130706433",      # Decimal integer representation of 127.0.0.1
        "0x7f000001",      # Hexadecimal integer representation of 127.0.0.1
    ]
    for target in loopbacks:
        with pytest.raises(SSRFSecurityException):
            validate_hostname_ssrf(target)


def test_ssrf_detects_rfc1918_private_ips():
    privates = [
        "10.0.0.1",
        "10.254.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.1.100",
    ]
    for target in privates:
        ip = parse_ip_literal(target)
        assert ip is not None
        blocked, reason = is_restricted_ip(ip)
        assert blocked is True
        assert "Private" in reason


def test_ssrf_detects_cloud_metadata():
    metadata_ips = ["169.254.169.254", "169.254.169.253", "100.100.100.200"]
    for ip_str in metadata_ips:
        ip = parse_ip_literal(ip_str)
        assert ip is not None
        blocked, reason = is_restricted_ip(ip)
        assert blocked is True
        assert "metadata" in reason.lower() or "link-local" in reason.lower()

    metadata_hosts = ["metadata.google.internal", "instance-data"]
    for host in metadata_hosts:
        with pytest.raises(SSRFSecurityException, match="Restricted internal"):
            validate_hostname_ssrf(host)


def test_ssrf_detects_internal_suffixes():
    suffixes = [
        "internal.corp",
        "server.local",
        "database.lan",
        "myhome.home.arpa",
        "dev.test",
        "app.internal",
    ]
    for host in suffixes:
        with pytest.raises(SSRFSecurityException, match="Restricted internal domain suffix"):
            validate_hostname_ssrf(host)


def test_ssrf_allows_public_ips_and_hostnames():
    public_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "2606:4700:4700::1111"]
    for ip_str in public_ips:
        ip = parse_ip_literal(ip_str)
        assert ip is not None
        blocked, _ = is_restricted_ip(ip)
        assert blocked is False

    # Valid public hostnames should not raise
    validate_hostname_ssrf("cloudflare.com")
    validate_hostname_ssrf("google.com")
    validate_hostname_ssrf("github.com")


# ==========================================
# 3. Deterministic Security Rules Engine Tests
# ==========================================

def test_security_rules_missing_https():
    features = {
        "normalized_domain": "insecure.example",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": False,
        "tls_supported": False,
        "hsts_header_present": False,
        "csp_header_present": False,
        "x_frame_options_present": False,
        "x_content_type_options_present": False,
        "cookies_observed_count": 0,
        "redirect_count": 0,
        "redirect_chain_contains_downgrade": False,
    }
    findings = evaluate_security_findings(features)
    f_map = {f["finding_id"]: f for f in findings}

    assert "TLS-MISSING-HTTPS" in f_map
    assert f_map["TLS-MISSING-HTTPS"]["severity"] == "CRITICAL"
    assert f_map["TLS-MISSING-HTTPS"]["status"] == "FAIL"


def test_security_rules_expired_and_weak_tls():
    features = {
        "normalized_domain": "expired-tls.example",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.0",
        "tls_cert_expired": True,
        "tls_cert_not_after": "2023-01-01T00:00:00Z",
        "tls_cert_remaining_days": -100,
        "tls_cert_is_self_signed": False,
        "tls_cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "header_hsts_present": False,
        "header_csp_present": False,
        "header_xfo_present": False,
        "header_xcto_present": False,
        "cookie_count": 0,
        "redirect_count": 0,
        "https_downgrade": False,
    }
    findings = evaluate_security_findings(features)
    f_map = {f["finding_id"]: f for f in findings}

    assert f_map["TLS-CERT-EXPIRED"]["status"] == "FAIL"
    assert f_map["TLS-CERT-EXPIRED"]["severity"] == "CRITICAL"
    assert f_map["TLS-VERSION-DEPRECATED"]["status"] == "FAIL"
    assert f_map["TLS-VERSION-DEPRECATED"]["severity"] == "HIGH"


def test_security_rules_insecure_cookies():
    features = {
        "normalized_domain": "cookies.example",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.3",
        "tls_cert_expired": False,
        "tls_cert_not_after": "2027-01-01T00:00:00Z",
        "tls_cert_remaining_days": 400,
        "tls_cert_is_self_signed": False,
        "header_hsts_present": True,
        "header_hsts_max_age": 31536000,
        "header_csp_present": True,
        "header_xfo_present": True,
        "header_xcto_present": True,
        "cookie_count": 2,
        "cookie_secure_count": 0,
        "cookie_httponly_count": 1,
        "cookie_all_secure": False,
        "cookie_all_httponly": False,
        "cookie_samesite_strict_count": 0,
        "cookie_samesite_lax_count": 0,
        "redirect_count": 0,
        "https_downgrade": False,
    }
    findings = evaluate_security_findings(features)
    f_map = {f["finding_id"]: f for f in findings}

    assert f_map["COOKIE-MISSING-SECURE"]["status"] == "FAIL"
    assert f_map["COOKIE-MISSING-SECURE"]["severity"] == "MEDIUM"
    assert f_map["COOKIE-MISSING-HTTPONLY"]["status"] == "WARN"
    assert f_map["COOKIE-MISSING-SAMESITE"]["status"] == "WARN"


def test_security_rules_redirect_downgrade():
    features = {
        "normalized_domain": "downgrade.example",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.3",
        "tls_cert_expired": False,
        "tls_cert_not_after": "2027-01-01T00:00:00Z",
        "tls_cert_remaining_days": 400,
        "tls_cert_is_self_signed": False,
        "header_hsts_present": True,
        "header_csp_present": True,
        "header_xfo_present": True,
        "header_xcto_present": True,
        "cookie_count": 0,
        "redirect_count": 2,
        "https_downgrade": True,
    }
    findings = evaluate_security_findings(features)
    f_map = {f["finding_id"]: f for f in findings}

    assert f_map["REDIR-INSECURE-DOWNGRADE"]["status"] == "FAIL"
    assert f_map["REDIR-INSECURE-DOWNGRADE"]["severity"] == "CRITICAL"


# ==========================================
# 4. ML Posture Predictor Tests
# ==========================================

def test_ml_predictor_loads_and_infers():
    predictor = MLSecurityPosturePredictor()
    assert predictor.is_available is True

    # Valid comprehensive feature profile
    features = {
        "normalized_domain": "good-example.org",
        "registrable_domain": "good-example.org",
        "domain_resolved": True,
        "dns_record_count": 2,
        "has_caa_record": True,
        "has_mx_record": True,
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.3",
        "tls_cert_valid": True,
        "tls_cert_expired": False,
        "tls_cert_remaining_days": 250,
        "tls_cert_is_self_signed": False,
        "hsts_header_present": True,
        "hsts_max_age": 31536000,
        "hsts_includes_subdomains": True,
        "hsts_preload": True,
        "csp_header_present": True,
        "csp_default_src_present": True,
        "csp_script_src_present": True,
        "csp_unsafe_inline": False,
        "csp_unsafe_eval": False,
        "x_frame_options_present": True,
        "x_frame_options_value": "DENY",
        "x_content_type_options_present": True,
        "x_content_type_options_nosniff": True,
        "referrer_policy_present": True,
        "referrer_policy_value": "strict-origin-when-cross-origin",
        "permissions_policy_present": True,
        "server_banner_present": False,
        "x_powered_by_present": False,
        "cookies_observed_count": 0,
        "cookies_missing_secure_count": 0,
        "cookies_missing_httponly_count": 0,
        "cookies_samesite_none_or_missing_count": 0,
        "redirect_count": 1,
        "redirect_chain_contains_downgrade": False,
        "http_to_https_redirect": True,
        "cors_wildcard_detected": False,
        "critical_findings_count": 0,
        "high_findings_count": 0,
        "medium_findings_count": 0,
        "low_findings_count": 0,
        "findings_count": 0,
        "collection_status": "SUCCESS",
    }
    pred = predictor.predict(features)
    assert pred["available"] is True
    assert pred["predicted_posture"] in ("GOOD", "MODERATE", "POOR")
    assert 0.0 <= pred["confidence"] <= 1.0
    assert "GOOD" in pred["probabilities"]
    assert "MODERATE" in pred["probabilities"]
    assert "POOR" in pred["probabilities"]
    # Verify probabilities sum to ~1.0
    total_prob = sum(pred["probabilities"].values())
    assert 0.99 <= total_prob <= 1.01


def test_ml_predictor_abstains_on_unresolved_domain():
    predictor = MLSecurityPosturePredictor()
    features = {
        "normalized_domain": "unresolved.example",
        "domain_resolved": False,
        "collection_status": "DNS_FAILURE",
    }
    pred = predictor.predict(features)
    assert pred["abstained"] is True
    assert pred["predicted_posture"] == "INSUFFICIENT_EVIDENCE"
    assert "resolution failed" in pred["abstention_reason"]


def test_ml_predictor_abstains_on_unreachable_host():
    predictor = MLSecurityPosturePredictor()
    features = {
        "normalized_domain": "unreachable.example",
        "domain_resolved": True,
        "collection_status": "UNREACHABLE",
    }
    pred = predictor.predict(features)
    assert pred["abstained"] is True
    assert pred["predicted_posture"] == "INSUFFICIENT_EVIDENCE"
    assert "unreachable" in pred["abstention_reason"]


# ==========================================
# 5. Risk Aggregator & Invariant Tests
# ==========================================

def test_risk_aggregator_deterministic_override_on_critical_finding():
    aggregator = RiskAggregator()
    features = {
        "normalized_domain": "vuln.example",
        "domain_resolved": True,
        "collection_status": "SUCCESS",
    }
    # Create findings with a CRITICAL failure
    findings = [
        {
            "finding_id": "TLS-CERT-EXPIRED",
            "category": "TLS_SECURITY",
            "name": "Expired Certificate",
            "severity": "CRITICAL",
            "status": "FAIL",
            "evidence": "Cert expired 30 days ago",
            "recommendation": "Renew certificate immediately.",
        }
    ]
    # ML optimistically predicted GOOD
    ml_result = {
        "available": True,
        "predicted_posture": "GOOD",
        "confidence": 0.92,
        "abstained": False,
    }

    result = aggregator.aggregate_assessment(features, findings, ml_result)

    # Invariant: Critical finding strictly forces POOR posture and DETERMINISTIC_OVERRIDE
    assert result["final_posture"] == "POOR"
    assert result["consensus"]["status"] == "DETERMINISTIC_OVERRIDE"
    assert "confirmed technical vulnerabilities strictly enforce POOR" in result["consensus"]["discrepancy_explanation"]


def test_risk_aggregator_remediation_priority_ordering():
    aggregator = RiskAggregator()
    features = {"normalized_domain": "test.example", "domain_resolved": True, "collection_status": "SUCCESS"}
    findings = [
        {"finding_id": "LOW-1", "severity": "LOW", "status": "FAIL", "category": "HDR", "recommendation": "Fix Low"},
        {"finding_id": "CRIT-1", "severity": "CRITICAL", "status": "FAIL", "category": "TLS", "recommendation": "Fix Crit"},
        {"finding_id": "MED-1", "severity": "MEDIUM", "status": "FAIL", "category": "COOKIE", "recommendation": "Fix Med"},
        {"finding_id": "HIGH-1", "severity": "HIGH", "status": "FAIL", "category": "HDR", "recommendation": "Fix High"},
    ]
    ml_result = {"available": True, "predicted_posture": "POOR", "confidence": 0.99, "abstained": False}
    result = aggregator.aggregate_assessment(features, findings, ml_result)

    remeds = result["remediations"]
    assert len(remeds) == 4
    assert remeds[0]["severity"] == "CRITICAL"
    assert remeds[1]["severity"] == "HIGH"
    assert remeds[2]["severity"] == "MEDIUM"
    assert remeds[3]["severity"] == "LOW"


def test_risk_aggregator_unreachable_endpoint():
    aggregator = RiskAggregator()
    features = {"normalized_domain": "dead.example", "domain_resolved": False, "collection_status": "UNREACHABLE"}
    findings = [
        {"finding_id": "DNS-FAIL", "category": "DNS", "name": "Resolution Failed", "severity": "INFO", "status": "UNKNOWN", "evidence": "Dead"}
    ]
    ml_result = {"available": True, "predicted_posture": "INSUFFICIENT_EVIDENCE", "abstained": True}
    result = aggregator.aggregate_assessment(features, findings, ml_result)

    assert result["final_posture"] == "INSUFFICIENT_EVIDENCE"
    assert result["security_score"] == 0.0
    assert result["consensus"]["status"] == "ABSTENTION_INSUFFICIENT_DATA"


# ==========================================
# 6. WebSecurityAnalyzer End-to-End Tests
# ==========================================

def test_analyzer_rejects_ssrf_without_network_call():
    analyzer = WebSecurityAnalyzer()
    # Spy on extractor to ensure extract_features is never invoked
    with patch.object(analyzer.extractor, "extract_features", new_callable=AsyncMock) as mock_extract:
        report = asyncio.run(analyzer.analyze_async("http://127.0.0.1:8080/internal"))
        mock_extract.assert_not_called()
        assert report.posture == "INSUFFICIENT_EVIDENCE"
        assert report.consensus.status == "PRE_VALIDATION_FAILURE"
        assert "SSRF" in report.findings[0].evidence


def test_analyzer_end_to_end_mocked_good_site():
    mock_features = {
        "normalized_domain": "mock-secure.org",
        "registrable_domain": "mock-secure.org",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "dns_record_count": 2,
        "has_caa_record": True,
        "has_mx_record": True,
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.3",
        "tls_cert_valid": True,
        "tls_cert_expired": False,
        "tls_cert_remaining_days": 300,
        "tls_cert_is_self_signed": False,
        "tls_cert_hostname_match": True,
        "tls_cert_sans": ["mock-secure.org"],
        "header_hsts_present": True,
        "header_hsts_max_age": 31536000,
        "header_hsts_include_subdomains": True,
        "header_hsts_preload": True,
        "header_csp_present": True,
        "header_csp_unsafe_inline": False,
        "header_csp_unsafe_eval": False,
        "header_xfo_present": True,
        "header_xfo_value": "DENY",
        "header_xcto_present": True,
        "header_referrer_policy_present": True,
        "header_referrer_policy_value": "strict-origin-when-cross-origin",
        "cookie_count": 0,
        "redirect_count": 1,
        "https_downgrade": False,
        "http_to_https_redirect": True,
        "server_version_exposed": False,
        "x_powered_by_present": False,
        "collection_status": "SUCCESS",
    }

    analyzer = WebSecurityAnalyzer()
    with patch.object(analyzer.extractor, "extract_features", new_callable=AsyncMock) as mock_extract:
        mock_extract.return_value = mock_features
        report = asyncio.run(analyzer.analyze_async("https://mock-secure.org"))

        assert isinstance(report, WebSecurityReport)
        assert report.posture == "GOOD"
        assert report.security_score >= 90.0
        assert report.findings_summary.critical_count == 0
        assert report.consensus.status == "CONSENSUS"


def test_analyzer_synchronous_wrapper():
    analyzer = WebSecurityAnalyzer()
    report = analyzer.analyze("http://localhost:9999/test")
    assert isinstance(report, WebSecurityReport)
    assert report.posture == "INSUFFICIENT_EVIDENCE"
    assert report.consensus.status == "PRE_VALIDATION_FAILURE"
