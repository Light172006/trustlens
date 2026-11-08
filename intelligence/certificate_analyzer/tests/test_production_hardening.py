"""Comprehensive production hardening, standards compliance, and resilience tests."""

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certificate_analyzer.api import analyze_certificate, analyze_pem
from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.errors import (
    AnalysisErrorCode,
    CertificateAnalyzerError,
    InvalidCertificateError,
)
from certificate_analyzer.rules.policy import CABFPolicyEvaluator
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding
from certificate_analyzer.scoring.engine import CertificateScoringEngine


def _generate_test_cert_pair(
    not_before: datetime,
    not_after: datetime,
    cn: str = "example.com",
    is_ca: bool = False,
    issuer_cert=None,
    issuer_key=None,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = issuer_cert.subject if issuer_cert else subject
    signing_key = issuer_key or key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )

    cert = builder.sign(signing_key, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    der = cert.public_bytes(serialization.Encoding.DER)
    return cert, pem, der, key


# ==============================================================================
# 1. CA/B FORUM v2.3.1 POLICY VERSIONING & ISSUANCE DATE TIERS
# ==============================================================================

def test_cabf_policy_tier_pre_2026():
    """Certificates issued before March 15, 2026 allow up to 398 days."""
    issuance = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # 395 days (Compliant)
    rec_pass = {"validity_duration_days": 395.0, "certificate_type": "LEAF"}
    eval_pass = CABFPolicyEvaluator.evaluate(rec_pass, not_before=issuance)
    assert eval_pass["applicability"] == "APPLICABLE"
    assert eval_pass["max_validity_days_allowed"] == 398.0
    assert eval_pass["validity_compliant"] is True
    assert eval_pass["applicable_rule_id"] == "CABF_398_DAYS"

    # 450 days (Non-Compliant)
    rec_fail = {"validity_duration_days": 450.0, "certificate_type": "LEAF"}
    eval_fail = CABFPolicyEvaluator.evaluate(rec_fail, not_before=issuance)
    assert eval_fail["validity_compliant"] is False


def test_cabf_policy_tier_2026_to_2027():
    """Certificates issued March 15, 2026 - March 14, 2027 allow up to 200 days."""
    issuance = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # 190 days (Compliant)
    rec_pass = {"validity_duration_days": 190.0, "certificate_type": "LEAF"}
    eval_pass = CABFPolicyEvaluator.evaluate(rec_pass, not_before=issuance)
    assert eval_pass["max_validity_days_allowed"] == 200.0
    assert eval_pass["validity_compliant"] is True
    assert eval_pass["applicable_rule_id"] == "CABF_2026_200_DAYS"

    # 250 days (Non-Compliant)
    rec_fail = {"validity_duration_days": 250.0, "certificate_type": "LEAF"}
    eval_fail = CABFPolicyEvaluator.evaluate(rec_fail, not_before=issuance)
    assert eval_fail["validity_compliant"] is False


def test_cabf_policy_tier_2027_to_2029():
    """Certificates issued March 15, 2027 - March 14, 2029 allow up to 100 days."""
    issuance = datetime(2027, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # 95 days (Compliant)
    rec_pass = {"validity_duration_days": 95.0, "certificate_type": "LEAF"}
    eval_pass = CABFPolicyEvaluator.evaluate(rec_pass, not_before=issuance)
    assert eval_pass["max_validity_days_allowed"] == 100.0
    assert eval_pass["validity_compliant"] is True
    assert eval_pass["applicable_rule_id"] == "CABF_2027_100_DAYS"

    # 120 days (Non-Compliant)
    rec_fail = {"validity_duration_days": 120.0, "certificate_type": "LEAF"}
    eval_fail = CABFPolicyEvaluator.evaluate(rec_fail, not_before=issuance)
    assert eval_fail["validity_compliant"] is False


def test_cabf_policy_tier_post_2029():
    """Certificates issued from March 15, 2029 allow up to 47 days."""
    issuance = datetime(2029, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # 45 days (Compliant)
    rec_pass = {"validity_duration_days": 45.0, "certificate_type": "LEAF"}
    eval_pass = CABFPolicyEvaluator.evaluate(rec_pass, not_before=issuance)
    assert eval_pass["max_validity_days_allowed"] == 47.0
    assert eval_pass["validity_compliant"] is True
    assert eval_pass["applicable_rule_id"] == "CABF_2029_47_DAYS"

    # 55 days (Non-Compliant)
    rec_fail = {"validity_duration_days": 55.0, "certificate_type": "LEAF"}
    eval_fail = CABFPolicyEvaluator.evaluate(rec_fail, not_before=issuance)
    assert eval_fail["validity_compliant"] is False


def test_cabf_policy_ca_not_applicable():
    """Root CAs and Intermediate CAs must be designated NOT_APPLICABLE rather than failing subscriber limits."""
    issuance = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    
    # Root CA with 10-year validity (3650 days)
    rec_root = {"validity_duration_days": 3650.0, "certificate_type": "ROOT"}
    eval_root = CABFPolicyEvaluator.evaluate(rec_root, not_before=issuance, is_ca=True, is_self_signed=True)
    assert eval_root["applicability"] == "NOT_APPLICABLE"
    assert eval_root["certificate_profile"] == "ROOT_CA"
    assert eval_root["max_validity_days_allowed"] is None
    assert eval_root["validity_compliant"] is None


# ==============================================================================
# 2. PEM BUNDLE LEAF RESOLUTION & AMBIGUITY HANDLING
# ==============================================================================

def test_inverted_bundle_leaf_resolution():
    """Analyzer must correctly identify the leaf even if an intermediate appears first in the bundle."""
    t_now = datetime.now(timezone.utc)
    ca_cert, ca_pem, _, ca_key = _generate_test_cert_pair(
        t_now, t_now + timedelta(days=3650), cn="Intermediate CA G1", is_ca=True
    )
    leaf_cert, leaf_pem, _, _ = _generate_test_cert_pair(
        t_now, t_now + timedelta(days=90), cn="app.example.com", is_ca=False,
        issuer_cert=ca_cert, issuer_key=ca_key
    )

    # Bundle with intermediate first, leaf second
    inverted_bundle = ca_pem + "\n" + leaf_pem

    assessment = analyze_pem(inverted_bundle, target_hostname="app.example.com", reference_time=t_now)
    assert "app.example.com" in assessment.subject_dn
    assert assessment.verdict in (CertificateVerdict.WARNING, CertificateVerdict.DISTRUSTED)


def test_ambiguous_bundle_without_hostname():
    """Bundle containing multiple independent leaves without hostname context returns INCONCLUSIVE."""
    t_now = datetime.now(timezone.utc)
    _, leaf1_pem, _, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="service-a.com")
    _, leaf2_pem, _, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="service-b.com")

    multi_leaf_bundle = leaf1_pem + "\n" + leaf2_pem
    assessment = analyze_pem(multi_leaf_bundle, reference_time=t_now)

    assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
    assert any(f.code == "RULE_AMBIGUOUS_BUNDLE_MULTIPLE_LEAVES" for f in assessment.findings)


def test_ambiguous_bundle_resolved_with_hostname():
    """Bundle containing multiple leaves resolves to the correct leaf when target_hostname matches."""
    t_now = datetime.now(timezone.utc)
    _, leaf1_pem, _, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="service-a.com")
    _, leaf2_pem, _, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="service-b.com")

    multi_leaf_bundle = leaf1_pem + "\n" + leaf2_pem
    assessment = analyze_pem(multi_leaf_bundle, target_hostname="service-b.com", reference_time=t_now)

    assert "service-b.com" in assessment.subject_dn
    assert assessment.verdict != CertificateVerdict.INCONCLUSIVE


# ==============================================================================
# 3. DEDUCTION DEDUPLICATION & SCORING INVARIANTS
# ==============================================================================

def test_duplicate_finding_deductions_prevented():
    """Duplicate findings sharing the same code must NOT deduct points multiple times."""
    features = CertificateFeatures()
    finding_1 = CertificateFinding(
        code="RULE_DEPRECATED_PUBLIC_KEY",
        title="Deprecated Public Key",
        severity=FindingSeverity.HIGH,
        description="Deprecated Key",
        score_deduction=35,
    )
    finding_2 = CertificateFinding(
        code="RULE_DEPRECATED_PUBLIC_KEY",
        title="Duplicate Finding",
        severity=FindingSeverity.HIGH,
        description="Duplicate",
        score_deduction=35,
    )

    # 100 - 35 = 65. If duplicate was applied, score would be 100 - 70 = 30.
    _, score, _ = CertificateScoringEngine.calculate([finding_1, finding_2], features)
    assert score == 65


# ==============================================================================
# 4. RESOURCE LIMITS & DOS RESILIENCE
# ==============================================================================

def test_oversized_input_rejection():
    """Inputs exceeding maximum size limit are rejected with RESOURCE_LIMIT_EXCEEDED."""
    huge_input = b"A" * (11 * 1024 * 1024)  # 11 MB
    assessment = analyze_certificate(huge_input)
    assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
    assert any(f.code == "RULE_RESOURCE_LIMIT_EXCEEDED" for f in assessment.findings)


def test_oversized_bundle_rejection():
    """Bundles exceeding MAX_BUNDLE_CERTS (50) are rejected safely."""
    t_now = datetime.now(timezone.utc)
    _, pem, _, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="single.com")
    huge_bundle = (pem + "\n") * 55
    assessment = analyze_pem(huge_bundle)
    assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
    assert any(f.code == "RULE_RESOURCE_LIMIT_EXCEEDED" for f in assessment.findings)


# ==============================================================================
# 5. STRUCTURED ERROR HIERARCHY
# ==============================================================================

def test_error_hierarchy_structures():
    err = InvalidCertificateError("Corrupt ASN.1", details={"byte_offset": 42})
    assert isinstance(err, CertificateAnalyzerError)
    assert err.error_code == AnalysisErrorCode.INVALID_CERTIFICATE
    d = err.to_dict()
    assert d["error_code"] == "INVALID_CERTIFICATE"
    assert d["details"]["byte_offset"] == 42


# ==============================================================================
# 6. ML ADVISORY INTEGRATION & NON-BLOCKING GUARANTEE
# ==============================================================================

def test_ml_advisory_opt_in():
    """When include_ml_advisory=True, advisory fields are attached without modifying verdict."""
    t_now = datetime.now(timezone.utc)
    _, _, der, _ = _generate_test_cert_pair(t_now, t_now + timedelta(days=90), cn="advisory.example.com")

    # Without ML advisory
    ass_base = analyze_certificate(der, target_hostname="advisory.example.com", reference_time=t_now)
    assert ass_base.ml_advisory is None

    # With ML advisory
    ass_advisory = analyze_certificate(der, target_hostname="advisory.example.com", reference_time=t_now, include_ml_advisory=True)
    if ass_advisory.ml_advisory is not None:
        assert "compliance_probability" in ass_advisory.ml_advisory
        assert "is_anomaly" in ass_advisory.ml_advisory
        assert ass_advisory.ml_advisory["is_advisory"] is True
    # Deterministic verdict must remain unchanged
    assert ass_advisory.verdict == ass_base.verdict
    assert ass_advisory.trust_score == ass_base.trust_score
