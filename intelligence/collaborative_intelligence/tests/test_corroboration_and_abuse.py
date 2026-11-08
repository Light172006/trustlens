"""Unit tests for independent corroboration, abuse detection, and reporter reliability."""

from datetime import datetime, timedelta, timezone
import pytest

from collaborative_intelligence.abuse_detection import AbuseDetector
from collaborative_intelligence.config import AbuseDetectionConfig, CorroborationConfig
from collaborative_intelligence.enums import (
    AbuseSignalType,
    CorroborationLevel,
    EvidenceStance,
    EvidenceType,
    ReporterReliabilityTier,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    CommunityReportInput,
    EvidenceItem,
    ReporterMetadata,
)
from collaborative_intelligence.corroboration import CorroborationEngine
from collaborative_intelligence.reporter_reliability import evaluate_reporter_reliability


def make_report(
    submission_id: str,
    reporter_id: str,
    evidence_items: list[EvidenceItem],
    submitted_at: datetime | None = None,
    category: ThreatCategory = ThreatCategory.PHISHING,
    description: str = "Suspicious site attempting login theft.",
    account_age_days: int = 60,
    accepted: int = 5,
    rejected: int = 0,
) -> CommunityReportInput:
    """Helper to construct deterministic CommunityReportInput."""
    return CommunityReportInput(
        submission_id=submission_id,
        original_url="https://phish.target.com/login",
        category=category,
        description=description,
        evidence_items=evidence_items,
        submitted_at=submitted_at or datetime.now(timezone.utc),
        reporter=ReporterMetadata(
            reporter_id=reporter_id,
            account_age_days=account_age_days,
            previous_accepted_reports=accepted,
            previous_rejected_reports=rejected,
        ),
    )


def test_single_unsupported_report_yields_none_or_low():
    """A single unverified report cannot produce high corroboration."""
    engine = CorroborationEngine()
    rep = make_report(
        submission_id="sub_1",
        reporter_id="user_1",
        evidence_items=[],
        description="I feel this is phishing.",
    )
    res = engine.evaluate_corroboration([rep])
    assert res.corroboration_level == CorroborationLevel.NONE
    assert res.independent_reporter_count == 1
    assert any("Zero supporting evidence" in w for w in res.weakening_reasons)


def test_multiple_independent_reports_diverse_evidence_yields_high():
    """Three genuinely independent reports with diverse verified evidence yield HIGH corroboration."""
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)

    r1 = make_report(
        "s1", "user_1",
        [EvidenceItem(
            evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
            source="scanner",
            description="Credential harvest form discovered.",
            is_verified=True,
        )],
        submitted_at=now,
    )
    r2 = make_report(
        "s2", "user_2",
        [EvidenceItem(
            evidence_type=EvidenceType.DNS_OBSERVATION,
            source="resolver",
            description="Newly registered domain with fast-flux IPs.",
            is_verified=True,
        )],
        submitted_at=now,
    )
    r3 = make_report(
        "s3", "user_3",
        [EvidenceItem(
            evidence_type=EvidenceType.CERTIFICATE_OBSERVATION,
            source="ct_monitor",
            description="Untrusted self-signed certificate impersonating bank.",
            is_verified=True,
        )],
        submitted_at=now,
    )

    res = engine.evaluate_corroboration([r1, r2, r3], reference_time=now)
    assert res.corroboration_level == CorroborationLevel.HIGH
    assert res.independent_reporter_count == 3
    assert res.evidence_diversity_score == 1.0
    assert res.conflicting_evidence_count == 0
    assert res.recommended_review_priority == ReviewPriority.URGENT


def test_multiple_accounts_identical_evidence_collapses_independence():
    """Ten accounts submitting identical copied evidence collapse to 1 independent source and flag abuse."""
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)

    # Identical evidence item reused across 5 accounts
    shared_evidence = [
        EvidenceItem(
            evidence_type=EvidenceType.SCREENSHOT,
            source="screenshot_tool",
            description="Exact identical screenshot binary dump 0xDEADBEEF.",
            is_verified=False,
        )
    ]

    reports = [
        make_report(f"s_{i}", f"user_{i}", shared_evidence, submitted_at=now)
        for i in range(5)
    ]

    res = engine.evaluate_corroboration(reports, reference_time=now)
    # Critical invariant: 5 accounts with copied evidence DO NOT equal 5 independent sources
    assert res.independent_reporter_count == 1
    assert res.total_reports_count == 5
    # Corroboration MUST NOT be HIGH
    assert res.corroboration_level != CorroborationLevel.HIGH
    assert any("collapsed to 1 genuinely independent" in w for w in res.weakening_reasons)
    assert any("Identical evidence fingerprint reused" in w for w in res.abuse_warnings)


def test_repeated_submissions_from_single_reporter():
    """Multiple submissions from the same account count as ONE independent reporter."""
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)

    r1 = make_report("s1", "same_user", [
        EvidenceItem(evidence_type=EvidenceType.BROWSER_WARNING, source="browser", description="Warning A", is_verified=True)
    ], submitted_at=now)
    r2 = make_report("s2", "same_user", [
        EvidenceItem(evidence_type=EvidenceType.BROWSER_WARNING, source="browser", description="Warning B", is_verified=True)
    ], submitted_at=now)
    r3 = make_report("s3", "same_user", [
        EvidenceItem(evidence_type=EvidenceType.BROWSER_WARNING, source="browser", description="Warning C", is_verified=True)
    ], submitted_at=now)

    res = engine.evaluate_corroboration([r1, r2, r3], reference_time=now)
    assert res.independent_reporter_count == 1
    assert res.total_reports_count == 3
    assert res.corroboration_level != CorroborationLevel.HIGH


def test_conflicting_evidence_prevents_high_corroboration():
    """Conflicting evidence prevents HIGH corroboration even with multiple reporters."""
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)

    r1 = make_report("s1", "user_1", [
        EvidenceItem(evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT, stance=EvidenceStance.SUPPORTS, source="user", description="Claim phish", is_verified=True)
    ], submitted_at=now)
    r2 = make_report("s2", "user_2", [
        EvidenceItem(evidence_type=EvidenceType.ANALYZER_FINDING, stance=EvidenceStance.CONTRADICTS, source="scanner", description="Verified clean host with EV cert", is_verified=True)
    ], submitted_at=now)

    res = engine.evaluate_corroboration([r1, r2], reference_time=now)
    assert res.conflicting_evidence_count == 1
    assert res.corroboration_level in (CorroborationLevel.NONE, CorroborationLevel.LOW)


def test_temporal_decay_stale_reports():
    """Reports older than 90 days suffer heavy decay and are flagged as stale."""
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=120)

    r1 = make_report("s1", "user_1", [
        EvidenceItem(evidence_type=EvidenceType.THREAT_FEED_MATCH, source="feed", description="Old match", is_verified=True)
    ], submitted_at=old_time)

    res = engine.evaluate_corroboration([r1], reference_time=now)
    assert res.temporal_relevance_score < 0.10
    assert any("Reports are stale" in w for w in res.weakening_reasons)


def test_burst_reporting_abuse_detection():
    """Burst reporting within a tight window is detected."""
    detector = AbuseDetector(config=AbuseDetectionConfig(burst_window_seconds=60, burst_threshold_per_host=3))
    now = datetime.now(timezone.utc)

    reports = [
        make_report(f"s_{i}", f"user_{i}", [], submitted_at=now + timedelta(seconds=i * 5))
        for i in range(4)
    ]

    res = detector.analyze_reports(reports)
    assert res.is_suspicious is True
    assert AbuseSignalType.BURST_REPORTING in res.signals


def test_reporter_reliability_invariants():
    """Verify reporter reliability principles: new accounts neutral, farming prevented, restricted penalized."""
    # 1. New account starts neutral (0.50, NEW)
    new_user = ReporterMetadata(reporter_id="brand_new", account_age_days=1)
    eval_new = evaluate_reporter_reliability(new_user)
    assert eval_new.calculated_reliability_score == 0.50
    assert eval_new.assessed_tier == ReporterReliabilityTier.NEW

    # 2. Farming rejected reports does not increase score
    farmer = ReporterMetadata(
        reporter_id="spammer",
        account_age_days=100,
        previous_accepted_reports=1,
        previous_rejected_reports=20,
    )
    eval_farmer = evaluate_reporter_reliability(farmer)
    assert eval_farmer.calculated_reliability_score < 0.30
    assert eval_farmer.assessed_tier == ReporterReliabilityTier.UNTESTED

    # 3. Restricted account is locked to restricted tier and low score
    restricted = ReporterMetadata(
        reporter_id="bad_actor",
        is_restricted=True,
        previous_accepted_reports=10,
    )
    eval_restricted = evaluate_reporter_reliability(restricted)
    assert eval_restricted.calculated_reliability_score == 0.10
    assert eval_restricted.assessed_tier == ReporterReliabilityTier.RESTRICTED

    # 4. Established verified reporter
    good_user = ReporterMetadata(
        reporter_id="analyst",
        account_age_days=200,
        previous_accepted_reports=20,
        previous_rejected_reports=1,
    )
    eval_good = evaluate_reporter_reliability(good_user)
    assert eval_good.calculated_reliability_score >= 0.85
    assert eval_good.assessed_tier == ReporterReliabilityTier.HIGHLY_RELIABLE

