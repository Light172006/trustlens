"""Tests for TrustLens Deterministic Risk Scoring Engine."""

import pytest

from trustlens_intelligence.config.constants import LayerCoverage, ProviderResultStatus, Verdict
from trustlens_intelligence.schemas.evidence import (
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.engine import RiskScoringEngine


def test_clean_site_full_coverage_verdict_safe(clean_site_evidence):
    """A site with 0 findings and complete coverage must receive a SAFE verdict."""
    engine = RiskScoringEngine()
    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.NO_MATCH),
    ]

    res = engine.score(
        evidence=clean_site_evidence,
        findings=[],
        provider_checks=provider_checks,
        has_decisive_malicious=False,
    )

    assert res.verdict == Verdict.SAFE
    assert res.score == 0
    assert res.coverage["threat_intel"] == LayerCoverage.COMPLETE
    assert res.confidence >= 0.85


def test_missing_provider_coverage_prevents_safe_verdict(clean_site_evidence):
    """CRITICAL: Score 0-24 with unavailable or stale feed MUST NOT produce SAFE."""
    engine = RiskScoringEngine()
    # URLhaus failed or timed out
    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.UNAVAILABLE),
    ]

    res = engine.score(
        evidence=clean_site_evidence,
        findings=[],
        provider_checks=provider_checks,
        has_decisive_malicious=False,
    )

    assert res.verdict == Verdict.INCONCLUSIVE
    assert res.score == 0
    assert res.coverage["threat_intel"] == LayerCoverage.PARTIAL


def test_decisive_malicious_scoring(phishing_site_evidence):
    """Decisive malicious rule overrides score and produces MALICIOUS with score 100."""
    engine = RiskScoringEngine()
    decisive_finding = Finding(
        code="OPENPHISH_URL_MATCH",
        category="threat_intel",
        title="OpenPhish Match",
        description="Matched in feed",
        severity="critical",
        points=100,
        remediation="Avoid URL",
        source="test",
    )
    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.MATCH, matched=True)
    ]

    res = engine.score(
        evidence=phishing_site_evidence,
        findings=[decisive_finding],
        provider_checks=provider_checks,
        has_decisive_malicious=True,
    )

    assert res.verdict == Verdict.MALICIOUS
    assert res.score == 100
    assert res.confidence >= 0.90


def test_high_additive_score_without_decisive_is_suspicious():
    """Score 75-100 without decisive rule produces SUSPICIOUS, never MALICIOUS."""
    engine = RiskScoringEngine()
    # Create multiple additive findings totalling 85 points
    findings = [
        Finding(
            code="CERT_CHAIN_INVALID",
            category="certificate",
            title="Chain Invalid",
            description="",
            severity="high",
            points=25,
            remediation="",
            source="",
        ),
        Finding(
            code="CERT_HOSTNAME_MISMATCH",
            category="certificate",
            title="Hostname Mismatch",
            description="",
            severity="high",
            points=25,
            remediation="",
            source="",
        ),
        Finding(
            code="CERT_EXPIRED",
            category="certificate",
            title="Expired",
            description="",
            severity="high",
            points=20,
            remediation="",
            source="",
        ),
        Finding(
            code="DOMAIN_RECENTLY_REGISTERED",
            category="domain_intelligence",
            title="Recent Domain",
            description="",
            severity="high",
            points=15,
            remediation="",
            source="",
        ),
    ]
    ev = ScanEvidence(
        original_url="https://misconfigured-site.org",
        scheme="https",
        http=HttpEvidence(status_code=200),
        tls=TlsCertificateEvidence(chain_valid=False),
    )
    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.NO_MATCH),
    ]

    res = engine.score(
        evidence=ev,
        findings=findings,
        provider_checks=provider_checks,
        has_decisive_malicious=False,
    )

    # 25 + 25 + 20 + 15 = 85
    assert res.score == 85
    assert res.verdict == Verdict.SUSPICIOUS  # Not MALICIOUS!


def test_failed_scan_is_inconclusive_with_null_score():
    """A failed scan worker result must produce INCONCLUSIVE and risk_score is None."""
    engine = RiskScoringEngine()
    ev = ScanEvidence(original_url="http://unreachable.example")
    res = engine.score(
        evidence=ev,
        findings=[],
        provider_checks=[],
        has_decisive_malicious=False,
        is_scan_failed=True,
    )

    assert res.verdict == Verdict.INCONCLUSIVE
    assert res.score is None
    assert res.confidence == 0.0


def test_additive_findings_deduplication(clean_site_evidence):
    """Passing duplicate findings with the same code must not artificially inflate the score."""
    engine = RiskScoringEngine()
    dup_findings = [
        Finding(
            code="SUSPICIOUS_IP_HOST",
            category="web_security",
            severity="high",
            title="IP address used as host",
            description="Raw IP",
            points=20,
            remediation="",
            source="rules",
        ),
        Finding(
            code="SUSPICIOUS_IP_HOST",
            category="web_security",
            severity="high",
            title="IP address used as host",
            description="Raw IP duplicate",
            points=20,
            remediation="",
            source="rules",
        ),
    ]
    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.NO_MATCH),
    ]

    res = engine.score(
        evidence=clean_site_evidence,
        findings=dup_findings,
        provider_checks=provider_checks,
        has_decisive_malicious=False,
    )

    # Must be 20 points, not 40 points
    assert res.score == 20
    assert res.details["raw_score"] == 20


