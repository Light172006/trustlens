"""Unit tests for X.509 certificate parsing."""


def test_parsing_valid_ecdsa(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "VALID_ECDSA")
    assert fixture["sha256_fingerprint"] is not None
    assert len(fixture["sha256_fingerprint"]) == 64
    assert fixture["public_key"]["algorithm"] == "ECDSA"
    assert fixture["public_key"]["key_size_bits"] == 256
    assert fixture["public_key"]["security_classification"] == "SECURE"
    assert "valid-ec.trustlens.test" in fixture["domain_identity"]["dns_san_entries"]
    assert fixture["extensions"]["basic_constraints"]["is_ca"] is False


def test_parsing_weak_rsa(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "WEAK_PUBLIC_KEY")
    assert fixture["public_key"]["algorithm"] == "RSA"
    assert fixture["public_key"]["key_size_bits"] == 1024
    assert fixture["public_key"]["security_classification"] == "INSECURE"


def test_parsing_self_signed(synthetic_fixtures):
    fixture = next(f for f in synthetic_fixtures if f.get("fixture_type") == "SELF_SIGNED")
    assert fixture["subject_dn"] == fixture["issuer_dn"]

