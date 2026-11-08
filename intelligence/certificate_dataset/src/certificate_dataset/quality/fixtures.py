"""Deterministic generator for synthetic test fixtures (Section 13).

All fixtures produced here are strictly marked data_origin = 'SYNTHETIC_TEST_FIXTURE'
and isolated in tests/fixtures/. They are NEVER mixed with production data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import sys

# Ensure isolated .deps is available
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certificate_dataset.parsing.parser import X509CertificateParser


class TestFixtureGenerator:
    """Generates synthetic, ephemeral test certificates for offline test coverage."""

    DATA_ORIGIN = "SYNTHETIC_TEST_FIXTURE"

    @classmethod
    def generate_all_fixtures(cls, output_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Generates the full suite of edge-case test fixtures and saves them to fixtures/."""
        if output_dir is None:
            output_dir = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "tests"
                / "fixtures"
            )
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        fixtures: List[Dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        # 1. Valid Modern ECDSA
        ec_key = ec.generate_private_key(ec.SECP256R1())
        cert_valid_ec = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "valid-ec.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(ec_key.public_key())
            .serial_number(1001)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("valid-ec.trustlens.test")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ec_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_valid_ec.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "VALID_ECDSA"
        fixtures.append(rec)

        # 2. Expired Certificate
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_expired = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1002)
            .not_valid_before(now - timedelta(days=400))
            .not_valid_after(now - timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("expired.trustlens.test")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_expired.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "EXPIRED"
        fixtures.append(rec)

        # 3. Not Yet Valid Certificate
        cert_not_yet = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1003)
            .not_valid_before(now + timedelta(days=30))
            .not_valid_after(now + timedelta(days=120))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("future.trustlens.test")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_not_yet.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "NOT_YET_VALID"
        fixtures.append(rec)

        # 4. Self-Signed Certificate
        self_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.trustlens.test")])
        cert_self = (
            x509.CertificateBuilder()
            .subject_name(self_name)
            .issuer_name(self_name)
            .public_key(rsa_key.public_key())
            .serial_number(1004)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("selfsigned.trustlens.test")]), critical=False)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_self.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "SELF_SIGNED"
        fixtures.append(rec)

        # 5. Missing SAN Extension
        cert_no_san = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-san.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1005)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_no_san.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "MISSING_SAN"
        fixtures.append(rec)

        # 6. Weak Public Key (RSA 1024-bit)
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        cert_weak_key = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak-key.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(weak_key.public_key())
            .serial_number(1006)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("weak-key.trustlens.test")]), critical=False)
            .sign(weak_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_weak_key.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "WEAK_PUBLIC_KEY"
        fixtures.append(rec)

        # 7. Deprecated Signature Algorithm (Simulated SHA-1)
        cert_sha1 = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sha1.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1007)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("sha1.trustlens.test")]), critical=False)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_sha1.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["signature"]["algorithm"] = "sha1WithRSAEncryption"
        rec["signature"]["hash_algorithm"] = "SHA1"
        rec["signature"]["security_classification"] = "DEPRECATED"
        rec["signature_algorithm"] = "sha1WithRSAEncryption"
        rec["fixture_type"] = "DEPRECATED_SIGNATURE"
        fixtures.append(rec)

        # 8. Incorrect CA Constraint (is_ca=True but no key_cert_sign)
        cert_bad_ca = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bad-ca.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1008)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True) # digital_signature & content_commitment only
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_bad_ca.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "INCORRECT_CA_CONSTRAINT"
        fixtures.append(rec)

        # 9. Incorrect EKU Profile (Only codeSigning for TLS server)
        cert_bad_eku = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bad-eku.trustlens.test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TrustLens CA")]))
            .public_key(rsa_key.public_key())
            .serial_number(1009)
            .not_valid_before(now - timedelta(days=10))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("bad-eku.trustlens.test")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .sign(rsa_key, hashes.SHA256())
        )
        rec = X509CertificateParser.parse(
            cert_bad_eku.public_bytes(serialization.Encoding.DER),
            source_name="synthetic_generator",
            data_origin=cls.DATA_ORIGIN,
        )
        rec["fixture_type"] = "INCORRECT_EKU"
        fixtures.append(rec)

        # Save fixtures to JSONL
        fixtures_file = output_dir / "synthetic_test_fixtures.jsonl"
        with open(fixtures_file, "w", encoding="utf-8") as f:
            import json
            for r in fixtures:
                f.write(json.dumps(r) + "\n")

        return fixtures
