"""Comprehensive stress tests for X.509 parsing, RFC 9525 identity, and path validation cache context separation."""

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import sys

# Ensure src and isolated .deps are on sys.path
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent
_ANALYZER_SRC = _INTELLIGENCE_DIR / "certificate_analyzer" / "src"
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
_DATASET_DEPS = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"

for p in [_ANALYZER_SRC, _DATASET_SRC, _DATASET_DEPS]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from certificate_analyzer.api import analyze_certificate, analyze_pem
from certificate_analyzer.engine.path_validator import CertificationPathValidator
from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_dataset.trust_stores.root_store import TrustStoreManager


def test_random_binary_garbage_fails_safely():
    """Confirms random bytes do not trigger unhandled exceptions."""
    for length in [10, 64, 256, 1024]:
        garbage = os.urandom(length)
        assessment = analyze_certificate(garbage)
        assert assessment.verdict.value == "INCONCLUSIVE"
        assert assessment.trust_score == 0
        codes = [f.code for f in assessment.findings]
        assert "RULE_MALFORMED_CERTIFICATE" in codes


def test_truncated_asn1_der_fails_safely():
    """Truncating authentic DER bytes fails safely without crash."""
    # Generate minimal valid DER
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "truncated.test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "truncated.test")]))
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    full_der = cert.public_bytes(serialization.Encoding.DER)
    # Truncate at half
    truncated = full_der[: len(full_der) // 2]
    assessment = analyze_certificate(truncated)
    assert assessment.verdict.value == "INCONCLUSIVE"
    assert "RULE_MALFORMED_CERTIFICATE" in [f.code for f in assessment.findings]


def test_malformed_pem_boundaries_fails_safely():
    """Corrupted PEM headers or bodies fail safely."""
    bad_pems = [
        "-----BEGIN CERTIFICATE-----\nNOT_BASE64_GARBAGE!@#$%\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "random non-pem text",
        "-----BEGIN CERTIFICATE-----\nMIIC\n",
    ]
    for bad in bad_pems:
        assessment = analyze_pem(bad)
        assert assessment.verdict.value == "INCONCLUSIVE"
        assert "RULE_MALFORMED_CERTIFICATE" in [f.code for f in assessment.findings]


def test_extremely_long_subject_string():
    """Certificates with oversized subject attributes parse safely."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    long_cn = "sub." + ("a" * 150) + ".example.com"
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, long_cn, _validate=False)]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.ca")]))
        .public_key(key.public_key())
        .serial_number(9999)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    assessment = analyze_certificate(der)
    assert assessment is not None
    assert assessment.verdict.value in ["WARNING", "DISTRUSTED", "TRUSTED"]


def test_rfc9525_ipv6_san_normalization():
    """RFC 9525 iPAddress SAN matching normalizes IPv6 formatting."""
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="2001:db8::1",
        dns_sans=[],
        ip_sans=["2001:0db8:0000:0000:0000:0000:0000:0001"],
    )
    assert matched is True
    assert status == "MATCH_IP"


def test_rfc9525_trailing_dots_on_reference_and_san():
    """Trailing dots in reference or SAN are stripped during normalization."""
    matched, status, pattern = RFC9525IdentityVerifier.verify(
        reference_identity="api.trustlens.io.",
        dns_sans=["api.trustlens.io."],
        ip_sans=[],
    )
    assert matched is True
    assert status == "MATCH_EXACT_DNS"


def test_path_validator_cache_context_separation():
    """Cache keys in CertificationPathValidator must respect reference time and trust store context."""
    # Generate CA and leaf
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    t_start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_mid = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_after = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Cache Test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Cache Test CA")]))
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(t_start)
        .not_valid_after(t_mid) # Expired at t_after
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf.test")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(t_start)
        .not_valid_after(t_after)
        .sign(ca_key, hashes.SHA256())
    )

    ts = TrustStoreManager()
    CertificationPathValidator.clear_cache()

    # Evaluation at t_start (CA is valid)
    res_valid = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[ca_cert],
        trust_store=ts,
        reference_time=t_start,
        store_name="MOZILLA",
    )

    # Evaluation at t_after (CA is expired!)
    res_expired = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[ca_cert],
        trust_store=ts,
        reference_time=t_after,
        store_name="MOZILLA",
    )

    # The two outcomes MUST differ and NOT return cached collision
    assert res_valid["verification_timestamp"] != res_expired["verification_timestamp"]
    assert any("PARENT_EXPIRED" in e for e in res_expired["validation_errors"])
    assert not any("PARENT_EXPIRED" in e for e in res_valid["validation_errors"])
