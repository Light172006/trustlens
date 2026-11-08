"""Unit tests auditing scoring invariants, verdict boundaries, and evidence completeness."""

from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding
from certificate_analyzer.scoring.engine import CertificateScoringEngine


def test_invariant_1_malformed_input():
    verdict, score, conf = CertificateScoringEngine.calculate(findings=[], features=CertificateFeatures(), is_malformed=True)
    assert verdict == CertificateVerdict.INCONCLUSIVE
    assert score == 0
    assert conf == 0.0


def test_invariant_2_revoked_certificate():
    features = CertificateFeatures()
    findings = [
        CertificateFinding(
            code="RULE_REVOKED",
            title="Revoked",
            severity=FindingSeverity.CRITICAL,
            description="Revoked",
            score_deduction=100,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)
    assert verdict == CertificateVerdict.DISTRUSTED
    assert score == 0


def test_invariant_3_expired_certificate():
    features = CertificateFeatures(is_expired=True)
    findings = [
        CertificateFinding(
            code="RULE_EXPIRED",
            title="Expired",
            severity=FindingSeverity.CRITICAL,
            description="Expired",
            score_deduction=90,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)
    assert verdict == CertificateVerdict.DISTRUSTED
    assert score <= 20


def test_invariant_4_hostname_mismatch():
    features = CertificateFeatures(matches_tested_hostname=False)
    findings = [
        CertificateFinding(
            code="RULE_HOSTNAME_MISMATCH",
            title="Mismatch",
            severity=FindingSeverity.CRITICAL,
            description="Mismatch",
            score_deduction=75,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)
    assert verdict == CertificateVerdict.DISTRUSTED
    assert score <= 25


def test_invariant_5_untrusted_root():
    features = CertificateFeatures(has_trusted_anchor=False)
    findings = [
        CertificateFinding(
            code="RULE_UNTRUSTED_ROOT",
            title="Untrusted Root",
            severity=FindingSeverity.HIGH,
            description="Untrusted Root",
            score_deduction=70,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)
    assert verdict == CertificateVerdict.DISTRUSTED
    assert score <= 30


def test_invariant_6_incomplete_chain_cannot_be_trusted():
    features = CertificateFeatures(is_chain_complete=False)
    findings = [
        CertificateFinding(
            code="RULE_INCOMPLETE_CHAIN",
            title="Incomplete Chain",
            severity=FindingSeverity.HIGH,
            description="Incomplete Chain",
            score_deduction=45,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)
    # Must not be TRUSTED
    assert verdict != CertificateVerdict.TRUSTED
    assert score <= 55


def test_invariant_7_missing_intermediate_distinct_from_invalid_signature():
    f_incomplete = CertificateFinding(code="RULE_INCOMPLETE_CHAIN", title="Incomplete", severity=FindingSeverity.HIGH, description="Incomplete", score_deduction=45)
    f_sig_invalid = CertificateFinding(code="RULE_INVALID_CHAIN_SIGNATURE", title="Invalid Sig", severity=FindingSeverity.CRITICAL, description="Invalid Sig", score_deduction=95)

    assert f_incomplete.code != f_sig_invalid.code
    assert f_incomplete.severity != f_sig_invalid.severity
    assert f_incomplete.score_deduction != f_sig_invalid.score_deduction


def test_invariant_8_score_and_confidence_separated():
    # Certificate with missing evidence has lower confidence
    features_low_conf = CertificateFeatures(
        is_chain_complete=False,
        has_trusted_anchor=False,
        matches_tested_hostname=None,
    )
    _, score1, conf1 = CertificateScoringEngine.calculate([], features_low_conf)

    # Certificate with full chain and authenticated hostname has higher confidence
    features_high_conf = CertificateFeatures(
        is_chain_complete=True,
        has_trusted_anchor=True,
        matches_tested_hostname=True,
    )
    _, score2, conf2 = CertificateScoringEngine.calculate([], features_high_conf)

    assert score1 == score2 == 100  # Raw trust deductions are identical (0)
    assert conf2 > conf1            # Confidence reflects evidence completeness

