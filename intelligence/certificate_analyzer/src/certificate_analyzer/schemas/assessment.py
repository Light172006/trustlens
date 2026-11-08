"""Assessment output schema for Certificate Analyzer."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from certificate_analyzer.constants import CURRENT_CERT_SCORING_VERSION, CertificateVerdict
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CertificateAssessment(BaseModel):
    """Authoritative certificate intelligence assessment produced by the Certificate Analyzer."""

    certificate_sha256: str = Field(..., description="SHA-256 fingerprint of the evaluated certificate")
    subject_dn: str = Field(default="", description="Subject Distinguished Name")
    issuer_dn: str = Field(default="", description="Issuer Distinguished Name")
    verdict: CertificateVerdict = Field(..., description="Overall digital trust verdict")
    trust_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Deterministic Certificate Trust Score (0-100); None if inconclusive",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence level based on evidence completeness and trust anchor resolution",
    )
    scoring_version: str = Field(default=CURRENT_CERT_SCORING_VERSION)
    checks_completed: int = Field(default=0, ge=0)
    findings: List[CertificateFinding] = Field(default_factory=list, description="Prioritized list of analysis findings")
    features: Optional[CertificateFeatures] = Field(default=None, description="Extracted feature vector")
    policy_evaluation: Optional[Dict[str, Any]] = Field(default=None, description="Versioned policy evaluation details")
    ml_advisory: Optional[Dict[str, Any]] = Field(default=None, description="Optional advisory ML compliance and profile anomaly signal")
    recommendations: List[str] = Field(default_factory=list, description="Actionable security recommendations")
    summary: str = Field(..., description="Executive human-readable summary of the certificate posture")
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of analysis",
    )

