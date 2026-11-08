"""Unit tests for revocation normalization and network security safeguards."""

import pytest
from certificate_dataset.revocation.collector import RevocationCollector
from certificate_dataset.revocation.network_guard import NetworkSafetyGuard, UnsafeURLError


def test_network_safety_guard_blocks_ssrf():
    # Loopback
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://127.0.0.1/test.crl")

    # Localhost
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://localhost:8080/ocsp")

    # RFC 1918 Private ranges
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://10.1.2.3/crl")
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://192.168.1.1/ocsp")
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://172.16.5.10/crl")

    # Link-local / Cloud metadata (169.254.169.254)
    with pytest.raises(UnsafeURLError):
        NetworkSafetyGuard.validate_url("http://169.254.169.254/latest/meta-data/")


def test_not_checked_revocation_observation():
    obs = RevocationCollector.create_not_checked_observation(
        certificate_fp="a" * 64,
        serial_number="1234abcd",
        issuer_dn="CN=Test CA",
    )
    assert obs["normalized_status"] == "NOT_CHECKED"
    assert obs["response_verification_result"] == "NOT_VERIFIED"
    assert obs["normalized_status"] != "GOOD"

