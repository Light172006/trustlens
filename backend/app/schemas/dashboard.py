"""Pydantic schemas for user dashboard metrics, verdict distribution, and recent scans."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DashboardVerdictCounts(BaseModel):
    """Counts across the four standard TrustLens verdicts."""

    SAFE: int = Field(default=0, ge=0)
    SUSPICIOUS: int = Field(default=0, ge=0)
    MALICIOUS: int = Field(default=0, ge=0)
    INCONCLUSIVE: int = Field(default=0, ge=0)


class DashboardSummaryMetrics(BaseModel):
    """Aggregate statistics scoped to the authenticated user."""

    total_scans: int = Field(default=0, ge=0)
    scans_last_30_days: int = Field(default=0, ge=0)
    verdict_counts: dict[str, int] = Field(
        default_factory=lambda: {
            "SAFE": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0,
            "INCONCLUSIVE": 0,
        }
    )
    active_scans: int = Field(default=0, ge=0)
    pending_community_reports: int = Field(default=0, ge=0)


class DashboardRecentScanItem(BaseModel):
    """Recent scan record displayed in dashboard activity view."""

    id: uuid.UUID
    canonical_url: str
    host: str
    status: str
    verdict: str
    risk_score: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class DashboardSummaryResponse(BaseModel):
    """Top-level response payload for GET /api/v1/dashboard/summary."""

    summary: DashboardSummaryMetrics
    recent_scans: list[DashboardRecentScanItem]
