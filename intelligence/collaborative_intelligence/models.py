"""TrustLens Collaborative Threat Intelligence — Domain Data Models.

Defines Pydantic v2 domain schemas for community reports, evidence,
corroboration assessments, abuse detection, moderation recommendations,
and confirmed indicators.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from collaborative_intelligence.enums import (
    AbuseSignalType,
    CorroborationLevel,
    DeduplicationStrength,
    EvidenceStance,
    EvidenceType,
    IndicatorScope,
    IndicatorStatus,
    ModerationAction,
    ReportStatus,
    ReporterReliabilityTier,
    ReviewPriority,
    ThreatCategory,
)


class EvidenceItem(BaseModel):
    """An individual piece of supporting or contradicting evidence with provenance."""

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType
    stance: EvidenceStance = EvidenceStance.SUPPORTS
    source: str = Field(..., max_length=256, description="Provenance source of the evidence")
    description: str = Field(..., max_length=4096, description="Description or extracted content of evidence")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reliability_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fingerprint: Optional[str] = Field(default=None, description="Cryptographic fingerprint of content for dedup")
    is_verified: bool = Field(default=False, description="True only if verified by an internal or authorized feed")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)

    @field_validator("observed_at")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        """Enforce timezone-aware datetimes."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class ReporterMetadata(BaseModel):
    """Metadata describing the reporting user account's historical track record."""

    reporter_id: str = Field(..., max_length=128)
    account_age_days: int = Field(default=0, ge=0)
    previous_accepted_reports: int = Field(default=0, ge=0)
    previous_rejected_reports: int = Field(default=0, ge=0)
    is_trusted: bool = Field(default=False)
    is_restricted: bool = Field(default=False)
    calculated_reliability_score: float = Field(default=0.5, ge=0.0, le=1.0)
    assessed_tier: ReporterReliabilityTier = ReporterReliabilityTier.NEW

    model_config = ConfigDict(frozen=True)


class CommunityReportInput(BaseModel):
    """Structured community report submitted to the intelligence engine."""

    submission_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    original_url: str = Field(..., min_length=3, max_length=2048)
    category: ThreatCategory = ThreatCategory.OTHER
    description: str = Field(default="", max_length=4096)
    evidence_items: List[EvidenceItem] = Field(default_factory=list, max_length=25)
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reporter: ReporterMetadata

    model_config = ConfigDict(frozen=True)

    @field_validator("submitted_at")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class ValidationResult(BaseModel):
    """Output of report and input syntax validation."""

    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    normalized_url: Optional[str] = None
    canonical_host: Optional[str] = None
    registrable_domain: Optional[str] = None

    model_config = ConfigDict(frozen=True)


class DuplicateMatch(BaseModel):
    """Details of a single duplicate or related match against an existing report."""

    matched_submission_id: str
    strength: DeduplicationStrength
    method: str
    explanation: str
    safe_to_group: bool

    model_config = ConfigDict(frozen=True)


class DeduplicationResult(BaseModel):
    """Result of duplicate detection across incoming and historical submissions."""

    is_duplicate: bool
    primary_submission_id: Optional[str] = None
    duplicate_matches: List[DuplicateMatch] = Field(default_factory=list)
    related_matches: List[DuplicateMatch] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class EvidenceEvaluationResult(BaseModel):
    """Evaluation of evidence quality, diversity, provenance, and credibility."""

    evidence_quality_score: float = Field(..., ge=0.0, le=1.0)
    evidence_diversity_score: float = Field(..., ge=0.0, le=1.0)
    supporting_count: int = Field(default=0, ge=0)
    contradicting_count: int = Field(default=0, ge=0)
    inconclusive_count: int = Field(default=0, ge=0)
    unverified_count: int = Field(default=0, ge=0)
    distinct_fingerprints: List[str] = Field(default_factory=list)
    evaluated_items: List[EvidenceItem] = Field(default_factory=list)
    explanations: List[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class AbuseDetectionResult(BaseModel):
    """Abuse, manipulation, or Sybil attack signals detected in reports."""

    is_suspicious: bool
    manipulation_risk: str = Field(default="LOW", description="LOW, MEDIUM, or HIGH")
    signals: List[AbuseSignalType] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class CorroborationAssessment(BaseModel):
    """Result of independent corroboration analysis across multiple reports and evidence."""

    corroboration_level: CorroborationLevel
    independent_reporter_count: int = Field(default=0, ge=0)
    total_reports_count: int = Field(default=0, ge=0)
    evidence_quality_score: float = Field(..., ge=0.0, le=1.0)
    evidence_diversity_score: float = Field(..., ge=0.0, le=1.0)
    temporal_relevance_score: float = Field(..., ge=0.0, le=1.0)
    conflicting_evidence_count: int = Field(default=0, ge=0)
    abuse_warnings: List[str] = Field(default_factory=list)
    supporting_reasons: List[str] = Field(default_factory=list)
    weakening_reasons: List[str] = Field(default_factory=list)
    recommended_review_priority: ReviewPriority = ReviewPriority.NORMAL

    model_config = ConfigDict(frozen=True)


class ModerationRecommendation(BaseModel):
    """Explainable action recommendation for authorized human moderators."""

    recommended_action: ModerationAction
    recommended_report_status: ReportStatus
    review_priority: ReviewPriority
    reasons: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    requires_human_approval: bool = Field(
        default=True,
        description="Strict invariant: Community threat confirmation always requires authorized human review.",
    )

    model_config = ConfigDict(frozen=True)


class ConfirmedIndicator(BaseModel):
    """A threat indicator that has been authorized and confirmed by moderators."""

    indicator_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    indicator_value: str = Field(..., description="Canonical URL, hostname, or domain")
    scope: IndicatorScope = IndicatorScope.EXACT_URL
    threat_category: ThreatCategory = ThreatCategory.PHISHING
    status: IndicatorStatus = IndicatorStatus.CONFIRMED
    confirmed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    disputed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    corroboration_level: CorroborationLevel = CorroborationLevel.MEDIUM
    moderator_id: str = Field(..., max_length=128)
    evidence_summary: str = Field(default="", max_length=4096)
    tags: List[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)

    @field_validator("confirmed_at", "expires_at", "disputed_at", "revoked_at")
    @classmethod
    def ensure_timezone_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class ConfirmedIndicatorMatch(BaseModel):
    """Result of querying a scan target against confirmed threat intelligence."""

    matched: bool
    target_url: str
    indicator: Optional[ConfirmedIndicator] = None
    matched_scope: Optional[IndicatorScope] = None
    is_active: bool = False
    explanation: str

    model_config = ConfigDict(frozen=True)


class ReportEvaluationResult(BaseModel):
    """Comprehensive intelligence output evaluating a community report submission."""

    submission_id: str
    canonical_url: str
    validation: ValidationResult
    deduplication: DeduplicationResult
    evidence_evaluation: EvidenceEvaluationResult
    abuse_detection: AbuseDetectionResult
    corroboration: CorroborationAssessment
    moderation_recommendation: ModerationRecommendation

    model_config = ConfigDict(frozen=True)

