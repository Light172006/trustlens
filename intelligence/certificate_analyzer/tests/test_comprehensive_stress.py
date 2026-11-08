"""Comprehensive stress, edge-case, and boundary tests for Certificate Analyzer."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certificate_analyzer.api import analyze_certificate
from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.engine.path_validator import CertificationPathValidator
from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding
from certificate_analyzer.scoring.engine import CertificateScoringEngine


def test_circular_chain_issuer_loop_prevention():
    """Verifies that circular issuer relationships terminate without infinite loops."""
    # Generate two certificates that cross-issue each other
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    now = datetime.now(timezone.utc)
    name1 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Circular Node A")])
    name2 = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Circular Node B")])
    
    # Cert 1 issued by Node B
    c1 = (
        x509.CertificateBuilder()
        .subject_name(name1)
        .issuer_name(name2)
        .public_key(k1.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(k2, hashes.SHA256())
    )
    
    # Cert 2 issued by Node A
    c2 = (
        x509.CertificateBuilder()
        .subject_name(name2)
        .issuer_name(name1)
        .public_key(k2.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(k1, hashes.SHA256())
    )
    
    from certificate_dataset.trust_stores.root_store import TrustStoreManager
    store = TrustStoreManager()
    
    t0 = time.time()
    result = CertificationPathValidator.validate_path(
        leaf_cert=c1,
        presented_intermediates=[c2],
        trust_store=store,
        reference_time=now,
    )
    dur = time.time() - t0
    
    assert dur < 0.5, "Path traversal must terminate quickly and not hang on circular graphs"
    assert result["validation_result"] in ("UNTRUSTED_ROOT", "INCOMPLETE_CHAIN")


def test_leap_year_boundary_handling():
    """Verifies that leap year dates (Feb 29) are handled without date arithmetic crashes."""
    # 2028 is a leap year; evaluate certificate valid through 2028-02-29
    leap_date = datetime(2028, 2, 29, 12, 0, 0, tzinfo=timezone.utc)
    
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leap-year.test")])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(datetime(2028, 2, 28, 0, 0, 0, tzinfo=timezone.utc))
        .not_valid_after(datetime(2028, 3, 1, 0, 0, 0, tzinfo=timezone.utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("leap-year.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(serialization.Encoding.DER)
    
    # Assess at leap day exact noon
    assessment = analyze_certificate(der, target_hostname="leap-year.test", reference_time=leap_date)
    assert assessment.verdict in (CertificateVerdict.TRUSTED, CertificateVerdict.WARNING, CertificateVerdict.DISTRUSTED)
    assert not any(f.code == "RULE_EXPIRED" for f in assessment.findings)
    assert not any(f.code == "RULE_NOT_YET_VALID" for f in assessment.findings)


def test_massive_san_list_rfc9525_stress():
    """Verifies RFC 9525 verification performance on a massive 500-domain SAN list."""
    domains = [f"sub{i}.cloud.cdn.example.org" for i in range(500)]
    target = "sub499.cloud.cdn.example.org"
    
    t0 = time.time()
    matched, status, matched_pattern = RFC9525IdentityVerifier.verify(
        reference_identity=target,
        dns_sans=domains,
        ip_sans=[],
    )
    dur = time.time() - t0
    
    assert matched is True
    assert status == "MATCH_EXACT_DNS"
    assert dur < 0.05, f"500-domain SAN matching took too long: {dur*1000:.2f} ms"


def test_conflicting_scoring_findings_stress():
    """Verifies that contradictory findings resolve strictly according to priority invariants."""
    features = CertificateFeatures(
        is_rsa=True,
        is_ecdsa=False,
        is_ed25519=False,
        key_size_bits=2048,
        is_weak_key=False,
        is_sha1=False,
        is_md5=False,
        is_secure_signature=True,
        validity_duration_days=90.0,
        days_since_issuance=10.0,
        days_until_expiry=80.0,
        is_expired=True,  # Contradictory flag: expired
        is_not_yet_valid=False,
        is_short_lived=True,
        san_count=1,
        has_san=True,
        has_wildcard=False,
        has_ip_san=False,
        matches_target_hostname=False,  # Contradictory flag: hostname mismatch
        is_self_signed=False,
        is_ca=False,
        chain_length=1,
        is_chain_complete=False,
        has_trusted_anchor=False,
        has_scts=True,
        is_cabf_validity_compliant=True,
        is_ca_constraint_compliant=True,
    )
    
    # Mix conflicting critical findings
    findings = [
        CertificateFinding(
            code="RULE_REVOKED",
            title="Certificate Revoked",
            severity=FindingSeverity.CRITICAL,
            description="Revoked",
            evidence={},
            recommendation="Replace",
            score_deduction=100,
        ),
        CertificateFinding(
            code="RULE_EXPIRED",
            title="Certificate Expired",
            severity=FindingSeverity.HIGH,
            description="Expired",
            evidence={},
            recommendation="Renew",
            score_deduction=40,
        ),
        CertificateFinding(
            code="RULE_HOSTNAME_MISMATCH",
            title="Hostname Mismatch",
            severity=FindingSeverity.HIGH,
            description="Mismatch",
            evidence={},
            recommendation="Fix SAN",
            score_deduction=35,
        ),
    ]
    
    verdict, score, confidence = CertificateScoringEngine.calculate(findings, features)
    
    # Invariant #2: Revoked certificate must unconditionally zero score and DISTRUSTED
    assert verdict == CertificateVerdict.DISTRUSTED
    assert score == 0
    assert confidence == 1.0
