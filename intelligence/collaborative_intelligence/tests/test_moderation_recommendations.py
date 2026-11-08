"""Unit tests for moderation recommendation advisor and queue prioritization."""

from datetime import datetime, timezone
import pytest

from collaborative_intelligence.enums import (
    CorroborationLevel,
    DeduplicationStrength,
    EvidenceStance,
    EvidenceType,
    ModerationAction,
    ReportStatus,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    CommunityReportInput,
    CorroborationAssessment,
    DeduplicationResult,
    DuplicateMatch,
    EvidenceItem,
    ModerationRecommendation,
    ReporterMetadata,
    ValidationResult,
)
from collaborative_intelligence.moderation import ModerationAdvisor


@pytest.fixture
def advisor():
    return ModerationAdvisor()


@pytest.fixture
def base_valid_result():
    return ValidationResult(
        is_valid=True,
        errors=[],
        warnings=[],
        normalized_url="https://phish.target.com/login",
    )


@pytest.fixture
def empty_dedup_result():
    return DeduplicationResult(
        is_duplicate=False,
        primary_submission_id=None,
        duplicate_matches=[],
        related_matches=[],
    )


def test_insufficient_evidence_recommendation(advisor, base_valid_result, empty_dedup_result):
    """Reports with missing evidence recommend REQUEST_MORE_EVIDENCE with LOW priority."""
    report = CommunityReportInput(
        submission_id="sub_1",
        original_url="https://phish.target.com/login",
        evidence_items=[],
        reporter=ReporterMetadata(reporter_id="u1"),
    )
    corrob = CorroborationAssessment(
        corroboration_level=CorroborationLevel.NONE,
        independent_reporter_count=1,
        total_reports_count=1,
        evidence_quality_score=0.0,
        evidence_diversity_score=0.0,
        temporal_relevance_score=1.0,
        conflicting_evidence_count=0,
        abuse_warnings=[],
        supporting_reasons=[],
        weakening_reasons=["No evidence provided."],
        recommended_review_priority=ReviewPriority.LOW,
    )

    rec = advisor.advise(report, base_valid_result, empty_dedup_result, corrob)
    assert rec.recommended_action == ModerationAction.REQUEST_MORE_EVIDENCE
    assert rec.recommended_report_status == ReportStatus.PENDING
    assert rec.review_priority == ReviewPriority.LOW
    assert rec.requires_human_approval is True
    assert any("zero verifiable supporting evidence" in w for w in rec.warnings)


def test_duplicate_report_recommendation(advisor, base_valid_result):
    """Canonical duplicate reports recommend AUTO_FLAG_DUPLICATE with status DUPLICATE."""
    report = CommunityReportInput(
        submission_id="sub_2",
        original_url="https://phish.target.com/login",
        evidence_items=[],
        reporter=ReporterMetadata(reporter_id="u2"),
    )
    dedup = DeduplicationResult(
        is_duplicate=True,
        primary_submission_id="sub_1",
        duplicate_matches=[
            DuplicateMatch(
                matched_submission_id="sub_1",
                strength=DeduplicationStrength.EXACT,
                method="RAW_URL_EXACT",
                explanation="Exact raw match",
                safe_to_group=True,
            )
        ],
    )
    corrob = CorroborationAssessment(
        corroboration_level=CorroborationLevel.LOW,
        independent_reporter_count=1,
        total_reports_count=2,
        evidence_quality_score=0.5,
        evidence_diversity_score=0.33,
        temporal_relevance_score=1.0,
        conflicting_evidence_count=0,
    )

    rec = advisor.advise(report, base_valid_result, dedup, corrob)
    assert rec.recommended_action == ModerationAction.AUTO_FLAG_DUPLICATE
    assert rec.recommended_report_status == ReportStatus.DUPLICATE
    assert rec.review_priority == ReviewPriority.LOW
    assert "sub_1" in rec.reasons[0]


def test_contradictory_evidence_recommendation(advisor, base_valid_result, empty_dedup_result):
    """Reports with contradictory evidence recommend human review with HIGH priority."""
    report = CommunityReportInput(
        submission_id="sub_3",
        original_url="https://phish.target.com/login",
        evidence_items=[
            EvidenceItem(
                evidence_type=EvidenceType.BROWSER_WARNING,
                stance=EvidenceStance.SUPPORTS,
                source="telemetry",
                description="Warning logged",
            )
        ],
        reporter=ReporterMetadata(reporter_id="u3"),
    )
    corrob = CorroborationAssessment(
        corroboration_level=CorroborationLevel.LOW,
        independent_reporter_count=1,
        total_reports_count=1,
        evidence_quality_score=0.3,
        evidence_diversity_score=0.33,
        temporal_relevance_score=1.0,
        conflicting_evidence_count=2,
    )

    rec = advisor.advise(report, base_valid_result, empty_dedup_result, corrob)
    assert rec.recommended_action == ModerationAction.QUEUE_FOR_REVIEW
    assert rec.recommended_report_status == ReportStatus.UNDER_REVIEW
    assert rec.review_priority == ReviewPriority.HIGH
    assert any("conflicting or contradictory" in w for w in rec.warnings)


def test_abuse_suspected_recommendation(advisor, base_valid_result, empty_dedup_result):
    """Reports flagged with abuse warnings recommend SUSPECT_ABUSE."""
    report = CommunityReportInput(
        submission_id="sub_4",
        original_url="https://phish.target.com/login",
        evidence_items=[],
        reporter=ReporterMetadata(reporter_id="u4"),
    )
    corrob = CorroborationAssessment(
        corroboration_level=CorroborationLevel.LOW,
        independent_reporter_count=1,
        total_reports_count=5,
        evidence_quality_score=0.4,
        evidence_diversity_score=0.33,
        temporal_relevance_score=1.0,
        conflicting_evidence_count=0,
        abuse_warnings=["Identical evidence fingerprint reused across multiple accounts."],
    )

    rec = advisor.advise(report, base_valid_result, empty_dedup_result, corrob)
    assert rec.recommended_action == ModerationAction.SUSPECT_ABUSE
    assert rec.recommended_report_status == ReportStatus.UNDER_REVIEW
    assert rec.review_priority == ReviewPriority.HIGH
    assert len(rec.warnings) > 0


def test_urgent_escalation_for_high_corroboration_malware(advisor, base_valid_result, empty_dedup_result):
    """High corroboration on severe threat (MALWARE) escalates to URGENT priority."""
    report = CommunityReportInput(
        submission_id="sub_5",
        original_url="https://phish.target.com/download.exe",
        category=ThreatCategory.MALWARE,
        evidence_items=[
            EvidenceItem(
                evidence_type=EvidenceType.THREAT_FEED_MATCH,
                source="urlhaus",
                description="Live payload delivery URL.",
                is_verified=True,
            )
        ],
        reporter=ReporterMetadata(reporter_id="u5"),
    )
    corrob = CorroborationAssessment(
        corroboration_level=CorroborationLevel.HIGH,
        independent_reporter_count=4,
        total_reports_count=4,
        evidence_quality_score=0.90,
        evidence_diversity_score=1.0,
        temporal_relevance_score=1.0,
        conflicting_evidence_count=0,
    )

    rec = advisor.advise(report, base_valid_result, empty_dedup_result, corrob)
    assert rec.recommended_action == ModerationAction.ESCALATE_URGENT
    assert rec.review_priority == ReviewPriority.URGENT
    assert rec.recommended_report_status == ReportStatus.UNDER_REVIEW
    assert rec.requires_human_approval is True

