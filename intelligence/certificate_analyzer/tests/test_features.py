"""Unit tests for CertificateFeatureExtractor."""

from certificate_analyzer.features.extractor import CertificateFeatureExtractor


def test_feature_extraction_ecdsa(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    features = CertificateFeatureExtractor.extract(fixture)

    assert features.is_ecdsa is True
    assert features.is_rsa is False
    assert features.key_size_bits == 256
    assert features.is_weak_key is False
    assert features.has_san is True
    assert features.validity_duration_days == 100.0
    assert features.is_expired is False


def test_feature_extraction_weak_key(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "WEAK_PUBLIC_KEY")
    features = CertificateFeatureExtractor.extract(fixture)

    assert features.is_rsa is True
    assert features.key_size_bits == 1024
    assert features.is_weak_key is True
