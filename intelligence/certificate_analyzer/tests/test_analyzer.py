"""End-to-end integration tests for CertificateAnalyzerEngine and public API."""

from datetime import datetime, timezone
from certificate_analyzer.api import analyze_certificate, analyze_endpoint_tls
from certificate_analyzer.constants import CertificateVerdict


def test_analyze_valid_fixture(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    assessment = analyze_certificate(
        fixture,
        target_hostname="valid-ec.trustlens.test",
        reference_time=datetime.now(timezone.utc),
    )

    assert assessment.verdict in (CertificateVerdict.TRUSTED, CertificateVerdict.WARNING)
    assert assessment.trust_score is not None
    assert assessment.trust_score >= 50
    assert assessment.confidence >= 0.7
    assert len(assessment.findings) > 0


def test_analyze_expired_fixture(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "EXPIRED")
    assessment = analyze_certificate(fixture, reference_time=datetime.now(timezone.utc))

    assert assessment.verdict == CertificateVerdict.DISTRUSTED
    assert assessment.trust_score <= 40
    assert any(f.code == "RULE_EXPIRED" for f in assessment.findings)


def test_analyze_malformed_input():
    assessment = analyze_certificate(b"NOT_A_VALID_DER_OR_PEM_CERTIFICATE")
    assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
    assert assessment.trust_score == 0
    assert any(f.code == "RULE_MALFORMED_CERTIFICATE" for f in assessment.findings)


def test_analyze_endpoint_tls(synthetic_fixtures):
    import base64
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    der_bytes = base64.b64decode(fixture["der_base64"])
    assessment = analyze_endpoint_tls(
        certificate_der=der_bytes,
        target_hostname="valid-ec.trustlens.test",
        port=443,
        tls_protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        reference_time=datetime.now(timezone.utc),
    )
    assert assessment.verdict in (CertificateVerdict.TRUSTED, CertificateVerdict.WARNING)
    assert assessment.trust_score is not None
    assert assessment.trust_score >= 50


