"""Pydantic v2 schemas for website security scan requests, reports, and detail views."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanStatus(str, Enum):
    """Scan execution states."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class Verdict(str, Enum):
    """Overall website security verdicts."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class ScanCreateRequest(BaseModel):
    """Payload for submitting a website URL for security analysis."""

    url: str = Field(..., max_length=2048, description="Target website HTTP or HTTPS URL")
    treat_as_sensitive: bool = Field(
        default=False,
        description="If True, skips external threat feed queries to protect private URL parameters",
    )


class ScanRecordResponse(BaseModel):
    """Baseline scan record representation."""

    id: uuid.UUID
    original_url: str
    canonical_url: str
    host: str
    scheme: str
    is_sensitive: bool
    status: str
    verdict: str
    risk_score: int | None = None
    scoring_version: str
    checks_completed: int
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_code: str | None = None
    failure_message: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanSubmitResponse(BaseModel):
    """Response returned upon scan submission (HTTP 202 or 200 deduplicated)."""

    scan: ScanRecordResponse
    deduplicated: bool = Field(
        default=False,
        description="True if an identical active scan was already queued within 60 seconds",
    )


class FindingResponseItem(BaseModel):
    """Structured security finding item."""

    id: uuid.UUID
    category: str
    code: str
    title: str
    description: str
    severity: str
    points: int
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    source: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanFindingsResponse(BaseModel):
    """List of findings for a specific scan."""

    scan_id: uuid.UUID
    items: list[FindingResponseItem]
    total: int


class CertificateResponseItem(BaseModel):
    """Leaf certificate representation."""

    host: str
    port: int = 443
    leaf_fingerprint_sha256: str
    subject_cn: str | None = None
    san_dns: list[str] = Field(default_factory=list)
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int | None = None
    chain_valid: bool
    hostname_match: bool
    sct_present: bool
    revocation_status: str = "not_checked"
    fetched_at: datetime

    # Deep Certificate Analyzer fields
    trust_score: int | None = None
    verdict: str | None = None
    confidence: float | None = None
    checks_completed: int | None = None
    policy_evaluation: dict[str, Any] | None = None
    ml_advisory: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    assessment_payload: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


class CertificateDetailResponse(BaseModel):
    """Certificate endpoint response."""

    scan_id: uuid.UUID
    available: bool
    certificate: CertificateResponseItem | None = None
    assessment: dict[str, Any] | None = None
    reason: str | None = None


class ProviderCheckResponseItem(BaseModel):
    """Provider check observation."""

    provider: str
    result_status: str
    matched: bool
    checked_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RedirectHopResponseItem(BaseModel):
    """Redirect hop item."""

    hop_index: int
    source_url: str
    destination_url: str
    http_status: int
    resolved_host: str
    resolved_ips: list[str] = Field(default_factory=list)
    tls_verified: bool = False

    model_config = ConfigDict(from_attributes=True)


class CoverageResponse(BaseModel):
    """Layer assessment coverage breakdown."""

    threat_intel: str = Field(
        default="complete", description="Coverage: complete, partial, unavailable, not_applicable"
    )
    web_security: str = Field(default="complete")
    certificate: str = Field(default="complete")
    community: str = Field(default="complete")


class ScanDetailResponse(BaseModel):
    """Comprehensive scan report detailing verdict, score, coverage, provider checks, and redirects."""

    scan: ScanRecordResponse
    coverage: CoverageResponse
    provider_checks: list[ProviderCheckResponseItem] = Field(default_factory=list)
    redirects: list[RedirectHopResponseItem] = Field(default_factory=list)


class ScanSummaryItem(BaseModel):
    """Compact summary of a scan record for list and dashboard views."""

    id: uuid.UUID
    canonical_url: str
    host: str
    status: str
    verdict: str
    risk_score: int | None = None
    scoring_version: str
    created_at: datetime
    completed_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)
