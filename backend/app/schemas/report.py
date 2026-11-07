"""Pydantic schemas for collaborative community reports, voting, and moderation."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ReportCategory = Literal[
    "phishing",
    "malware",
    "scam",
    "credential_harvesting",
    "unsolicited_bulk",
    "other",
]
ClaimedVerdict = Literal["MALICIOUS", "SUSPICIOUS", "SAFE"]
ReportStatus = Literal["pending", "confirmed", "rejected", "duplicate"]
VoteType = Literal["confirm", "false_positive"]
ModerationDecision = Literal["confirmed", "rejected", "duplicate"]


class CommunityReportCreateRequest(BaseModel):
    """Payload to submit a suspicious website for community threat review."""

    url: str = Field(..., max_length=2048, description="Target website URL")
    scan_id: uuid.UUID | None = Field(
        default=None,
        description="Optional ID of an owned scan associated with this report",
    )
    category: ReportCategory = Field(..., description="Threat classification")
    claimed_verdict: ClaimedVerdict = Field(
        default="MALICIOUS",
        description="User claimed risk verdict",
    )
    evidence_text: str = Field(
        ...,
        min_length=20,
        max_length=2000,
        description="Plain-text explanation and observed indicator evidence (20-2000 chars)",
    )


class CommunityReportResponse(BaseModel):
    """Created or deduplicated community report record."""

    id: uuid.UUID
    canonical_url: str
    host: str
    category: str
    claimed_verdict: str
    status: str
    evidence_text: str
    created_at: datetime
    moderated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class CommunityReportSubmitResponse(BaseModel):
    """Envelope returned upon report submission, indicating whether it was deduplicated."""

    report: CommunityReportResponse
    duplicate_submission: bool


class PublicCommunityReportItem(BaseModel):
    """Confirmed community threat report displayed in public listings."""

    id: uuid.UUID
    canonical_url: str
    host: str
    category: str
    claimed_verdict: str
    status: str
    evidence_summary: str
    confirmation_count: int = Field(default=0, ge=0)
    false_positive_count: int = Field(default=0, ge=0)
    created_at: datetime
    moderated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UserCommunityReportItem(BaseModel):
    """User-scoped report record displayed in personal submission history."""

    id: uuid.UUID
    canonical_url: str
    category: str
    claimed_verdict: str
    status: str
    evidence_text: str
    moderation_reason: str | None = None
    created_at: datetime
    moderated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class CommunityReportDetailData(BaseModel):
    """Detailed community threat report data."""

    id: uuid.UUID
    canonical_url: str
    host: str
    category: str
    claimed_verdict: str
    status: str
    evidence_summary: str
    confirmation_count: int = Field(default=0, ge=0)
    false_positive_count: int = Field(default=0, ge=0)
    moderation_reason: str | None = None
    created_at: datetime
    moderated_at: datetime | None = None


class CommunityReportDetailResponse(BaseModel):
    """Envelope returned for GET /api/v1/community/reports/{id}."""

    report: CommunityReportDetailData


class CommunityVoteRequest(BaseModel):
    """Payload to endorse or dispute a confirmed community report."""

    vote: VoteType = Field(..., description="Endorsement type: confirm or false_positive")


class CommunityVoteCounts(BaseModel):
    """Aggregated confirmation and dispute tallies."""

    confirm: int = Field(default=0, ge=0)
    false_positive: int = Field(default=0, ge=0)


class CommunityVoteResponse(BaseModel):
    """Response returned upon casting or updating a community vote."""

    report_id: uuid.UUID
    vote: str
    updated: bool
    counts: CommunityVoteCounts


class AdminReportItem(BaseModel):
    """Report record displayed in the moderator triage queue."""

    id: uuid.UUID
    canonical_url: str
    host: str
    category: str
    claimed_verdict: str
    status: str
    evidence_text: str
    reporter_id: uuid.UUID
    confirmation_count: int = Field(default=0, ge=0)
    false_positive_count: int = Field(default=0, ge=0)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ModerationDecisionRequest(BaseModel):
    """Payload submitted by a moderator to confirm, reject, or duplicate a report."""

    decision: ModerationDecision = Field(
        ...,
        description="Moderation outcome: confirmed, rejected, or duplicate",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Auditable justification for the moderation decision (10-1000 chars)",
    )


class ModeratedReportData(BaseModel):
    """Moderated report status fields."""

    id: uuid.UUID
    status: str
    moderator_user_id: uuid.UUID
    moderation_reason: str
    moderated_at: datetime


class ModerationDecisionResponse(BaseModel):
    """Response returned upon successfully moderating a report."""

    report: ModeratedReportData
    audit_event_id: uuid.UUID


class ProviderHealthItem(BaseModel):
    """Operational freshness and health telemetry for a threat feed provider."""

    provider: str
    enabled: bool
    status: str
    last_success_at: datetime | None = None
    freshness_seconds: int | None = None
    freshness_limit_seconds: int | None = None
    records_active: int | None = None


class ProviderHealthResponse(BaseModel):
    """Provider health list returned for GET /api/v1/admin/providers."""

    providers: list[ProviderHealthItem]
