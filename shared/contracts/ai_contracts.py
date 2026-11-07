"""Typed integration contracts between TrustLens Backend and the AI Intelligence Engine."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    """Authoritative scan verdict values."""

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingCategory(str, Enum):
    """Categories for scan and detection findings."""

    THREAT_INTEL = "threat_intel"
    WEB_SECURITY = "web_security"
    CERTIFICATE = "certificate"
    COMMUNITY = "community"
    DOMAIN_INTELLIGENCE = "domain_intelligence"


class FindingSeverity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProviderResultStatus(str, Enum):
    """Standardized result status from threat intelligence provider lookups."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    NOT_CONFIGURED = "not_configured"
    SKIPPED_SENSITIVE_URL = "skipped_sensitive_url"
    STALE_CACHE = "stale_cache"


class LayerCoverage(str, Enum):
    """Layer coverage status."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class HttpObservation(BaseModel):
    """Observed HTTP layer security properties."""

    status_code: Optional[int] = None
    redirect_count: int = 0
    final_url: Optional[str] = None
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None

    model_config = ConfigDict(extra="ignore")


class TlsObservation(BaseModel):
    """Observed SSL/TLS certificate and handshake properties."""

    valid: bool = False
    hostname_match: bool = False
    chain_valid: bool = False
    days_until_expiry: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san_dns: List[str] = Field(default_factory=list)
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class DomainIntelligence(BaseModel):
    """Domain registration and DNS telemetry."""

    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    has_mx_records: bool = False

    model_config = ConfigDict(extra="ignore")


class ThreatIntelligenceObservation(BaseModel):
    """External reputation and feed match observations."""

    phishing_match: bool = False
    malware_match: bool = False
    openphish_status: str = "no_match"
    urlhaus_status: str = "no_match"
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class CommunityIntelligenceObservation(BaseModel):
    """Aggregated community reports and votes for target."""

    confirmed_report_count: int = 0
    pending_report_count: int = 0
    confirmation_vote_count: int = 0
    false_positive_vote_count: int = 0

    model_config = ConfigDict(extra="ignore")


class ScanEvidence(BaseModel):
    """Normalized scan evidence container conforming to the intelligence engine's ScanEvidence model."""

    scan_id: str
    url: str
    domain: str
    is_sensitive: bool = False
    http: HttpObservation = Field(default_factory=HttpObservation)
    tls: TlsObservation = Field(default_factory=TlsObservation)
    domain_intelligence: DomainIntelligence = Field(default_factory=DomainIntelligence)
    threat_intelligence: ThreatIntelligenceObservation = Field(default_factory=ThreatIntelligenceObservation)
    community_intelligence: CommunityIntelligenceObservation = Field(default_factory=CommunityIntelligenceObservation)

    model_config = ConfigDict(extra="ignore")


class AssessmentFinding(BaseModel):
    """A structured finding representing an evaluated risk or security observation."""

    id: Optional[str] = None
    code: str = Field(..., description="Stable programmatic identifier for the finding")
    category: FindingCategory
    title: str = Field(..., description="Short explanatory finding title")
    description: str = Field(..., description="Detailed description of the observation and risk")
    severity: FindingSeverity
    points: int = Field(default=0, ge=0, le=100)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: str = Field(..., description="Recommended remediation action")
    source: str = Field(..., description="Rule engine or attribution source")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")


class AIAssessment(BaseModel):
    """Authoritative threat intelligence assessment produced by the TrustLens Intelligence Engine."""

    verdict: Verdict
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    scoring_version: str = Field(default="trustlens-1.0")
    checks_completed: int = Field(default=4)
    findings: List[AssessmentFinding] = Field(default_factory=list)
    summary: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

