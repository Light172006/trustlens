"""Unit tests for multi-dimensional certificate security and policy labels."""

from datetime import datetime, timezone
from certificate_dataset.labeling.labeler import CertificateLabeler


def test_hostname_matching():
    labeler = CertificateLabeler()
    record = {
        "sha256_fingerprint": "0" * 64,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "validity": {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T23:59:59Z",
        },
        "subject_dn": "CN=test.trustlens.io",
        "issuer_dn": "CN=Test CA",
        "domain_identity": {
            "subject_alternative_names": ["api.trustlens.io", "*.corp.trustlens.io"],
            "san_count": 2,
        },
        "record_quality_status": "VALID_PARSED",
        "public_key": {"security_classification": "SECURE"},
        "signature": {"security_classification": "SECURE"},
        "extensions": {"basic_constraints": {"is_ca": False}, "key_usage": []},
    }

    # Exact match
    res_exact = labeler.evaluate(record, reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc), target_hostname="api.trustlens.io")
    assert res_exact["labels"]["HOSTNAME_MATCH"] == "PASS"

    # Wildcard match
    res_wc = labeler.evaluate(record, reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc), target_hostname="auth.corp.trustlens.io")
    assert res_wc["labels"]["HOSTNAME_MATCH"] == "PASS"

    # Wildcard must not match apex or multiple levels (RFC 6125)
    res_wc_apex = labeler.evaluate(record, reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc), target_hostname="corp.trustlens.io")
    assert res_wc_apex["labels"]["HOSTNAME_MATCH"] == "FAIL"

    res_mismatch = labeler.evaluate(record, reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc), target_hostname="phishing.io")
    assert res_mismatch["labels"]["HOSTNAME_MATCH"] == "FAIL"


def test_weak_public_key_and_signature_labels(synthetic_fixtures):
    labeler = CertificateLabeler()
    weak_key = next(f for f in synthetic_fixtures if f.get("fixture_type") == "WEAK_PUBLIC_KEY")
    res_key = labeler.evaluate(weak_key)
    assert res_key["labels"]["WEAK_PUBLIC_KEY"] == "PASS"

    sha1_cert = next(f for f in synthetic_fixtures if f.get("fixture_type") == "DEPRECATED_SIGNATURE")
    res_sig = labeler.evaluate(sha1_cert)
    assert res_sig["labels"]["WEAK_SIGNATURE"] == "PASS"

