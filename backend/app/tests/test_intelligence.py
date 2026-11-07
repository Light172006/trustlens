"""Automated tests for AI Intelligence Engine integration boundary and contracts."""

from app.integrations.intelligence_client import intelligence_client
from shared.contracts.ai_contracts import (
    CommunityIntelligenceObservation,
    HttpObservation,
    ScanEvidence,
    ThreatIntelligenceObservation,
    TlsObservation,
    Verdict,
)


def test_clean_website_assessment_returns_safe() -> None:
    """Verify clean website technical observations produce SAFE verdict."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000001",
        url="https://example.com",
        domain="example.com",
        is_sensitive=False,
        http=HttpObservation(
            status_code=200,
            redirect_count=0,
            security_headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
            },
        ),
        tls=TlsObservation(
            valid=True,
            hostname_match=True,
            chain_valid=True,
            days_until_expiry=90,
            issuer="CN=Example CA",
            subject="CN=example.com",
        ),
        threat_intelligence=ThreatIntelligenceObservation(
            phishing_match=False,
            malware_match=False,
            openphish_status="no_match",
            urlhaus_status="no_match",
        ),
        community_intelligence=CommunityIntelligenceObservation(),
    )

    assessment = intelligence_client.analyze(evidence)
    assert assessment.verdict == Verdict.SAFE
    assert 0 <= assessment.risk_score <= 24
    assert assessment.confidence >= 0.85
    assert assessment.scoring_version == "trustlens-1.0"


def test_decisive_threat_match_returns_malicious() -> None:
    """Verify decisive phishing indicator produces MALICIOUS verdict with risk_score 100."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000002",
        url="https://phishing-site.invalid/login",
        domain="phishing-site.invalid",
        is_sensitive=False,
        threat_intelligence=ThreatIntelligenceObservation(
            phishing_match=True,
            openphish_status="match",
        ),
    )

    assessment = intelligence_client.analyze(evidence)
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score == 100
    assert assessment.confidence >= 0.90
    assert any(f.code == "DECISIVE_THREAT_INDICATOR_MATCH" for f in assessment.findings)


def test_community_confirmed_reports_returns_malicious() -> None:
    """Verify multiple moderator-confirmed reports produce MALICIOUS verdict."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000003",
        url="https://scam-site.invalid/verify",
        domain="scam-site.invalid",
        is_sensitive=False,
        community_intelligence=CommunityIntelligenceObservation(
            confirmed_report_count=3,
        ),
    )

    assessment = intelligence_client.analyze(evidence)
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score == 90
    assert any(f.code == "COMMUNITY_CONFIRMED_INDICATOR" for f in assessment.findings)


def test_invalid_tls_and_missing_hsts_returns_suspicious() -> None:
    """Verify invalid certificate and security header gaps return SUSPICIOUS."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000004",
        url="https://bad-cert.invalid",
        domain="bad-cert.invalid",
        is_sensitive=False,
        http=HttpObservation(
            status_code=200,
            security_headers={},  # Missing HSTS and CSP
        ),
        tls=TlsObservation(
            valid=False,
            chain_valid=False,
            hostname_match=False,
        ),
        threat_intelligence=ThreatIntelligenceObservation(
            openphish_status="no_match",
            urlhaus_status="no_match",
        ),
    )

    assessment = intelligence_client.analyze(evidence)
    assert assessment.verdict == Verdict.SUSPICIOUS
    assert assessment.risk_score >= 25


def test_sensitive_url_returns_inconclusive() -> None:
    """Verify sensitive scan URL with skipped provider lookup yields INCONCLUSIVE, never false SAFE."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000005",
        url="https://payments.example.com/checkout?token=secret123",
        domain="payments.example.com",
        is_sensitive=True,
        http=HttpObservation(
            status_code=200,
            security_headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
        ),
        tls=TlsObservation(
            valid=True,
            hostname_match=True,
            chain_valid=True,
            days_until_expiry=120,
        ),
        threat_intelligence=ThreatIntelligenceObservation(
            openphish_status="no_match",
            urlhaus_status="skipped_sensitive_url",
        ),
    )

    assessment = intelligence_client.analyze(evidence)
    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert any(f.code == "COVERAGE_INSUFFICIENT" for f in assessment.findings)


def test_worker_failure_returns_inconclusive_with_zero_confidence() -> None:
    """Verify worker unrecoverable crash produces safe INCONCLUSIVE verdict."""
    evidence = ScanEvidence(
        scan_id="00000000-0000-0000-0000-000000000006",
        url="https://crash.example.com",
        domain="crash.example.com",
    )

    assessment = intelligence_client.analyze(evidence, is_scan_failed=True)
    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.confidence == 0.0
    assert any(f.code == "SCAN_EXECUTION_FAILED" for f in assessment.findings)
