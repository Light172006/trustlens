"""Tests for TrustLens Intelligence Schemas and Contracts."""

import pytest
from pydantic import ValidationError

from trustlens_intelligence.config.constants import FindingCategory, FindingSeverity, ProviderResultStatus, Verdict
from trustlens_intelligence.schemas.assessment import ThreatAssessment
from trustlens_intelligence.schemas.evidence import (
    CookieEvidence,
    HttpEvidence,
    RedirectHopEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult


def test_scan_evidence_normalization():
    """Verify host, scheme, and canonical_url auto-inference."""
    ev = ScanEvidence(original_url="https://WWW.Sub.Example.COM:443/Path?q=1#frag")
    assert ev.scheme == "https"
    assert ev.host == "www.sub.example.com"
    assert ev.canonical_url == "https://WWW.Sub.Example.COM:443/Path?q=1#frag"


def test_http_evidence_header_normalization():
    """Header keys must be normalized to lowercase."""
    http = HttpEvidence(
        status_code=200,
        security_headers={
            "Content-Security-Policy": "default-src 'self'",
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
        },
    )
    assert "content-security-policy" in http.security_headers
    assert "strict-transport-security" in http.security_headers


def test_cookie_evidence_validation():
    """Cookie schema stores name, secure, httponly, samesite."""
    cookie = CookieEvidence(name="session_id", secure=True, httponly=True, samesite="Strict")
    assert cookie.name == "session_id"
    assert cookie.secure is True
    assert cookie.samesite == "Strict"


def test_finding_schema_and_serialization():
    """Verify Finding schema fields and serialization."""
    finding = Finding(
        code="CERT_EXPIRED",
        category=FindingCategory.CERTIFICATE,
        title="TLS Certificate Expired",
        description="The certificate expired 10 days ago.",
        severity=FindingSeverity.HIGH,
        points=20,
        evidence={"days_expired": 10},
        remediation="Renew certificate immediately.",
        source="trustlens_detection_rules_v1",
    )
    dumped = finding.model_dump()
    assert dumped["code"] == "CERT_EXPIRED"
    assert dumped["severity"] == "high"
    assert dumped["points"] == 20
    assert dumped["evidence"]["days_expired"] == 10


def test_provider_check_result_schema():
    """Verify ProviderCheckResult construction."""
    res = ProviderCheckResult(
        provider="openphish",
        result_status=ProviderResultStatus.MATCH,
        matched=True,
        details={"feed": "community"},
    )
    assert res.matched is True
    assert res.result_status == ProviderResultStatus.MATCH


def test_threat_assessment_api_dict_contract():
    """Verify ThreatAssessment to_api_dict conforms to API.md."""
    assessment = ThreatAssessment(
        scan_id="scan_123",
        verdict=Verdict.SUSPICIOUS,
        risk_score=42,
        confidence=0.85,
        scoring_version="trustlens-1.0",
        checks_completed=4,
        coverage={"threat_intel": "complete", "web_security": "complete"},
        findings=[],
        summary="Suspicious website activity.",
    )
    api_dict = assessment.to_api_dict()
    assert api_dict["scan_id"] == "scan_123"
    assert api_dict["verdict"] == "SUSPICIOUS"
    assert api_dict["risk_score"] == 42
    assert api_dict["confidence"] == 0.85
    assert api_dict["coverage"]["threat_intel"] == "complete"


def test_scan_evidence_adversarial_and_edge_case_inputs():
    """Verify ScanEvidence handles adversarial and malformed URL structures gracefully."""
    import pytest
    from pydantic import ValidationError

    # Empty and whitespace URLs must raise ValidationError
    with pytest.raises(ValidationError):
        ScanEvidence(original_url="")
    with pytest.raises(ValidationError):
        ScanEvidence(original_url="   ")

    # Malformed IPv6 brackets must not crash instantiation
    ev_bracket = ScanEvidence(original_url="http://[invalid:ipv6:here]/test")
    assert ev_bracket.scheme == "http"

    # Out-of-range port
    ev_port = ScanEvidence(original_url="http://example.com:99999/")
    assert ev_port.host == "example.com"


