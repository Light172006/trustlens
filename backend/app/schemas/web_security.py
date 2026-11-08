"""Pydantic schemas for Web Security Posture Analysis."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WebSecurityAnalyzeRequest(BaseModel):
    """Request payload to analyze website security posture."""

    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="Target website URL to analyze (HTTP or HTTPS)",
        examples=["https://example.com"],
    )
    force_fresh: bool = Field(
        default=False,
        description="Whether to perform fresh telemetry extraction",
    )


class SecurityFindingItem(BaseModel):
    """Individual security posture finding."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    category: str
    name: str
    severity: str
    status: str
    evidence: str
    detection_method: str = "DETERMINISTIC_RULE_INSPECTION"
    confidence: float = 1.0
    guidance: str | None = None
    recommendation: str | None = None


class MLPredictionItem(BaseModel):
    """Machine learning posture classification and confidence details."""

    model_config = ConfigDict(extra="ignore")

    available: bool = False
    predicted_posture: str
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float = 0.0
    margin: float | None = None
    abstained: bool = False
    abstention_reason: str | None = None
    model_name: str | None = None
    model_version: str | None = None


class ConsensusItem(BaseModel):
    """Consensus between deterministic rules and machine learning model."""

    model_config = ConfigDict(extra="ignore")

    status: str
    discrepancy_explanation: str | None = None


class FindingsSummaryItem(BaseModel):
    """Aggregate metrics of security findings."""

    model_config = ConfigDict(extra="ignore")

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    pass_count: int = 0
    affected_categories: list[str] = Field(default_factory=list)


class RemediationItem(BaseModel):
    """Prioritized remediation recommendation item."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    severity: str
    category: str
    recommendation: str


class WebSecurityAssessmentResponse(BaseModel):
    """Comprehensive web security posture assessment response."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: uuid.UUID | None = None
    target_url: str
    normalized_domain: str
    registrable_domain: str
    scan_timestamp: str
    scanner_version: str = "1.0.0"
    posture: str
    security_score: float
    deterministic_posture: str
    ml_prediction: MLPredictionItem
    consensus: ConsensusItem
    findings_summary: FindingsSummaryItem
    findings: list[SecurityFindingItem] = Field(default_factory=list)
    remediations: list[RemediationItem] = Field(default_factory=list)
    telemetry: dict[str, Any] = Field(default_factory=dict)
    summary_text: str | None = None
    scanned_at: datetime | None = None


class WebSecurityScanSummaryItem(BaseModel):
    """Condensed summary item for paginated listing of web security scans."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_url: str
    normalized_domain: str
    posture: str
    security_score: float
    total_findings: int
    critical_count: int
    high_count: int
    scanned_at: datetime


class WebSecurityScanListResponse(BaseModel):
    """Paginated collection of web security scans."""

    items: list[WebSecurityScanSummaryItem]
    total: int
    page: int
    limit: int
