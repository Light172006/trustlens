"""Deep unit tests for RFC 5280 certification path validation."""

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certificate_analyzer.api import analyze_pem
from certificate_analyzer.constants import CertificateVerdict
from certificate_analyzer.engine.path_validator import CertificationPathValidator
from certificate_dataset.trust_stores.root_store import TrustStoreManager


def _build_test_pki_hierarchy():
    """Builds a deterministic 3-tier PKI hierarchy: Root CA -> Intermediate CA -> Leaf."""
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Custom Root CA")])
    inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Custom Intermediate CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.example.test")])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=100))
        .not_valid_after(now + timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True) # key_cert_sign, crl_sign
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_name)
        .issuer_name(root_name)
        .public_key(inter_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=50))
        .not_valid_after(now + timedelta(days=500))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(inter_name)
        .public_key(leaf_key.public_key())
        .serial_number(3)
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("service.example.test")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()), critical=False)
        .sign(inter_key, hashes.SHA256())
    )

    return root_cert, inter_cert, leaf_cert


def test_chain_incomplete_when_intermediate_missing():
    root_cert, inter_cert, leaf_cert = _build_test_pki_hierarchy()
    ts_manager = TrustStoreManager()

    # Pass only leaf cert without presented intermediate
    result = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[],
        trust_store=ts_manager,
    )

    assert result["validation_result"] == "INCOMPLETE_CHAIN"
    assert result["is_complete"] is False
    assert "MISSING_INTERMEDIATE_CERTIFICATE" in result["validation_errors"]


def test_chain_untrusted_root_when_not_in_trust_store():
    root_cert, inter_cert, leaf_cert = _build_test_pki_hierarchy()
    ts_manager = TrustStoreManager() # Empty custom store

    result = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[inter_cert, root_cert],
        trust_store=ts_manager,
    )

    assert result["validation_result"] == "UNTRUSTED_ROOT"
    assert result["is_complete"] is True
    assert result["has_trusted_anchor"] is False


def test_chain_expired_intermediate_node():
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired Intermediate CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.test")])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=200))
        .not_valid_after(now + timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Intermediate was valid between 100 days ago and 10 days ago (expired today)
    inter_cert_expired = (
        x509.CertificateBuilder()
        .subject_name(inter_name)
        .issuer_name(root_name)
        .public_key(inter_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=100))
        .not_valid_after(now - timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(inter_name)
        .public_key(leaf_key.public_key())
        .serial_number(3)
        .not_valid_before(now - timedelta(days=5))
        .not_valid_after(now + timedelta(days=50))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("leaf.example.test")]), critical=False)
        .sign(inter_key, hashes.SHA256())
    )

    ts_manager = TrustStoreManager()
    result = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[inter_cert_expired, root_cert],
        trust_store=ts_manager,
        reference_time=now,
    )

    assert result["validation_result"] == "EXPIRED_CHAIN_NODE"


def test_chain_basic_constraints_violation_on_parent():
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    fake_ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    fake_ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake CA (ca=False)")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sub.example.test")])

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=100))
        .not_valid_after(now + timedelta(days=1000))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Parent has ca=False (violates RFC 5280)
    fake_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(fake_ca_name)
        .issuer_name(root_name)
        .public_key(fake_ca_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=50))
        .not_valid_after(now + timedelta(days=500))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(fake_ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(3)
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=50))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("sub.example.test")]), critical=False)
        .sign(fake_ca_key, hashes.SHA256())
    )

    ts_manager = TrustStoreManager()
    result = CertificationPathValidator.validate_path(
        leaf_cert=leaf_cert,
        presented_intermediates=[fake_ca_cert, root_cert],
        trust_store=ts_manager,
    )

    assert result["validation_result"] == "BASIC_CONSTRAINTS_VIOLATION"


def test_multi_certificate_pem_bundle_parsing():
    root_cert, inter_cert, leaf_cert = _build_test_pki_hierarchy()
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    inter_pem = inter_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # Construct fullchain.pem bundle string (leaf followed by intermediate)
    fullchain_bundle = f"{leaf_pem}\n{inter_pem}"

    assessment = analyze_pem(
        pem_str=fullchain_bundle,
        target_hostname="service.example.test",
    )

    assert assessment.verdict != CertificateVerdict.INCONCLUSIVE
    assert assessment.certificate_sha256 is not None
    # Intermediates were successfully unpacked and chain evaluated
    assert assessment.features.chain_length >= 2

