"""Unit tests for CertificateScoringEngine."""

from certificate_analyzer.constants import CertificateVerdict, FindingSeverity
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding
from certificate_analyzer.scoring.engine import CertificateScoringEngine


def test_clean_certificate_scoring():
    features = CertificateFeatures(
        is_chain_complete=True,
        has_trusted_anchor=True,
        matches_tested_hostname=True,
    )
    findings = []
    verdict, score, confidence = CertificateScoringEngine.calculate(findings, features)

    assert verdict == CertificateVerdict.TRUSTED
    assert score == 100
    assert confidence == 1.0


def test_expired_certificate_scoring():
    features = CertificateFeatures(is_expired=True)
    findings = [
        CertificateFinding(
            code="RULE_EXPIRED",
            title="Certificate Expired",
            severity=FindingSeverity.CRITICAL,
            description="Expired",
            score_deduction=90,
        )
    ]
    verdict, score, _ = CertificateScoringEngine.calculate(findings, features)

    assert verdict == CertificateVerdict.DISTRUSTED
    assert score <= 10

