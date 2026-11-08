"""Unit tests for CertificateRuleEngine."""

from datetime import datetime, timezone
from certificate_analyzer.features.extractor import CertificateFeatureExtractor
from certificate_analyzer.rules.engine import CertificateRuleEngine
from certificate_analyzer.schemas.context import EndpointTLSContext


def test_expired_rule_triggers_on_expired_fixture(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "EXPIRED")
    features = CertificateFeatureExtractor.extract(fixture, reference_time=datetime.now(timezone.utc))
    engine = CertificateRuleEngine()

    findings = engine.evaluate_all(features, fixture)
    codes = [f.code for f in findings]
    assert "RULE_EXPIRED" in codes


def test_hostname_mismatch_rule():
    record = {
        "sha256_fingerprint": "1" * 64,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-12-31T23:59:59Z",
        "domain_identity": {
            "subject_alternative_names": ["secure.example.com"],
            "has_wildcard": False,
            "san_count": 1,
        },
        "certificate_type": "LEAF",
        "public_key": {"algorithm": "RSA", "key_size_bits": 2048, "security_classification": "ACCEPTABLE"},
        "signature": {"algorithm": "sha256WithRSAEncryption", "security_classification": "SECURE"},
        "extensions": {"basic_constraints": {"is_ca": False}, "key_usage": []},
    }
    context = EndpointTLSContext(target_hostname="attacker.com")
    features = CertificateFeatureExtractor.extract(record, context=context, reference_time=datetime(2026, 6, 1, tzinfo=timezone.utc))
    engine = CertificateRuleEngine()

    findings = engine.evaluate_all(features, record, context=context)
    codes = [f.code for f in findings]
    assert "RULE_HOSTNAME_MISMATCH" in codes

