"""Deep unit tests for revocation observation handling under RFC 6960 / RFC 5280."""

from datetime import datetime, timedelta, timezone
from certificate_analyzer.api import analyze_certificate
from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.rules.revocation_verifier import RevocationRules


def test_revoked_status_enforces_zero_score_and_distrusted(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    now = datetime.now(timezone.utc)

    rev_obs = {
        "observation_id": "rev-test-1",
        "certificate_sha256_fingerprint": fixture["sha256_fingerprint"],
        "serial_number": fixture["serial_number"],
        "issuer_dn": fixture["issuer_dn"],
        "revocation_method": "OCSP",
        "normalized_status": "REVOKED",
        "revocation_reason": "keyCompromise",
        "revocation_timestamp": (now - timedelta(days=2)).isoformat(),
        "this_update": (now - timedelta(days=2)).isoformat(),
        "next_update": (now + timedelta(days=5)).isoformat(),
        "responder_identity": "CN=OCSP Responder",
        "response_verification_result": "VERIFIED",
        "evidence_source_url": "http://ocsp.example.test",
        "retrieval_timestamp": now.isoformat(),
    }

    assessment = analyze_certificate(
        fixture,
        revocation_observation=rev_obs,
        reference_time=now,
    )

    assert assessment.verdict == CertificateVerdict.DISTRUSTED
    assert assessment.trust_score == 0
    assert any(f.code == "RULE_REVOKED" for f in assessment.findings)
    assert any(f.severity == FindingSeverity.CRITICAL for f in assessment.findings)


def test_verified_good_ocsp_status(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    now = datetime.now(timezone.utc)

    good_obs = {
        "observation_id": "rev-test-good",
        "certificate_sha256_fingerprint": fixture["sha256_fingerprint"],
        "serial_number": fixture["serial_number"],
        "issuer_dn": fixture["issuer_dn"],
        "revocation_method": "OCSP",
        "normalized_status": "GOOD",
        "revocation_reason": None,
        "this_update": (now - timedelta(hours=1)).isoformat(),
        "next_update": (now + timedelta(hours=24)).isoformat(),
        "responder_identity": "CN=OCSP Responder",
        "response_verification_result": "VERIFIED",
        "evidence_source_url": "http://ocsp.example.test",
        "retrieval_timestamp": now.isoformat(),
    }

    findings = RevocationRules.evaluate_revocation_observation(good_obs, reference_time=now)
    codes = [f.code for f in findings]
    assert "RULE_REVOCATION_VERIFIED_GOOD" in codes
    assert "RULE_REVOKED" not in codes


def test_stale_expired_ocsp_response():
    now = datetime.now(timezone.utc)

    # next_update was yesterday (expired)
    stale_obs = {
        "observation_id": "rev-test-stale",
        "certificate_sha256_fingerprint": "1" * 64,
        "serial_number": "1234",
        "issuer_dn": "CN=CA",
        "revocation_method": "OCSP",
        "normalized_status": "GOOD",
        "this_update": (now - timedelta(days=5)).isoformat(),
        "next_update": (now - timedelta(days=1)).isoformat(),
        "responder_identity": "CN=OCSP Responder",
        "response_verification_result": "VERIFIED",
        "retrieval_timestamp": now.isoformat(),
    }

    findings = RevocationRules.evaluate_revocation_observation(stale_obs, reference_time=now)
    codes = [f.code for f in findings]
    assert "RULE_REVOCATION_RESPONSE_EXPIRED" in codes


def test_unknown_revocation_never_converts_to_good():
    now = datetime.now(timezone.utc)
    unknown_obs = {
        "observation_id": "rev-test-unknown",
        "certificate_sha256_fingerprint": "1" * 64,
        "serial_number": "1234",
        "issuer_dn": "CN=CA",
        "revocation_method": "OCSP",
        "normalized_status": "UNKNOWN",
        "retrieval_timestamp": now.isoformat(),
    }

    findings = RevocationRules.evaluate_revocation_observation(unknown_obs, reference_time=now)
    codes = [f.code for f in findings]
    assert "RULE_REVOCATION_UNKNOWN" in codes
    assert "RULE_REVOCATION_VERIFIED_GOOD" not in codes

