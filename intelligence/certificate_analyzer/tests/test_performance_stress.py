"""Stress testing, malformed inputs, and deterministic reproducibility tests."""

from datetime import datetime, timezone
from certificate_analyzer.api import analyze_certificate
from certificate_analyzer.constants import CertificateVerdict


def test_malformed_corrupt_inputs():
    corrupt_cases = [
        b"",
        b"\x00" * 32,
        b"RANDOM_GARBAGE_BYTES_NOT_ASN1",
        b"-----BEGIN CERTIFICATE-----\nINVALID_BASE64_DATA===\n-----END CERTIFICATE-----",
        "NOT_A_VALID_STRING",
    ]

    for corrupt in corrupt_cases:
        assessment = analyze_certificate(corrupt)
        assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
        assert assessment.trust_score == 0
        assert assessment.confidence == 0.0
        assert any(f.code == "RULE_MALFORMED_CERTIFICATE" for f in assessment.findings)


def test_deterministic_reproducibility(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    ref_time = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Run analysis 5 times
    assessments = [
        analyze_certificate(fixture, target_hostname="valid-ec.trustlens.test", reference_time=ref_time)
        for _ in range(5)
    ]

    first = assessments[0]
    for other in assessments[1:]:
        assert other.certificate_sha256 == first.certificate_sha256
        assert other.verdict == first.verdict
        assert other.trust_score == first.trust_score
        assert other.confidence == first.confidence
        assert [f.code for f in other.findings] == [f.code for f in first.findings]
        assert other.summary == first.summary


def test_large_san_list_performance():
    # Build a record with 100 SAN entries
    sans = [f"sub{i}.domain{i}.example.test" for i in range(100)]
    record = {
        "sha256_fingerprint": "a" * 64,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "domain_identity": {
            "subject_alternative_names": sans,
            "dns_san_entries": sans,
            "ip_san_entries": [],
            "has_wildcard": False,
            "san_count": len(sans),
        },
        "certificate_type": "LEAF",
        "public_key": {"algorithm": "ECDSA", "key_size_bits": 256, "security_classification": "SECURE"},
        "signature": {"algorithm": "ecdsa-with-SHA256", "security_classification": "SECURE"},
        "extensions": {"basic_constraints": {"is_ca": False}, "key_usage": []},
    }

    import time
    start = time.perf_counter()
    assessment = analyze_certificate(
        record,
        target_hostname="sub77.domain77.example.test",
        reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    elapsed = time.perf_counter() - start

    assert elapsed < 0.1  # Must complete in under 100ms
    assert assessment.verdict in (CertificateVerdict.TRUSTED, CertificateVerdict.WARNING)
    assert any(f.code == "RULE_HOSTNAME_MATCHED" for f in assessment.findings)
