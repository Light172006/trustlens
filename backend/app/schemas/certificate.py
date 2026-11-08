"""Pydantic schemas for the TrustLens Certificate Analyzer."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FindingEvidenceItem(BaseModel):
    code: str
    title: str
    severity: str
    description: str
    evidence: dict[str, Any] | None = None
    recommendation: str | None = None
    score_deduction: int = 0


class PolicyEvaluationSchema(BaseModel):
    policy_name: str
    policy_version: str
    certificate_profile: str
    applicability: str
    applicable_rule_id: str
    certificate_issuance_date: str
    evaluation_date: str
    max_validity_days_allowed: float | None = None
    actual_validity_days: float
    validity_compliant: bool | None = None
    cryptographic_compliant: bool
    overall_compliant: bool | None = None
    evaluation_notes: str


class MLAdvisorySchema(BaseModel):
    predicted_class: str
    compliance_probability: float
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    advisory_notes: str
    model_version: str = "1.0.0"
    is_advisory: bool = True


class CertificateFeaturesSchema(BaseModel):
    public_key_algorithm: str
    key_size_bits: int | None = None
    is_rsa: bool = False
    is_ecdsa: bool = False
    is_ed25519: bool = False
    is_weak_key: bool = False
    signature_algorithm: str
    is_sha1_signature: bool = False
    is_md5_signature: bool = False
    is_secure_signature: bool = True
    validity_duration_days: float
    days_since_issuance: float
    days_until_expiry: float
    is_expired: bool = False
    is_not_yet_valid: bool = False
    is_short_lived: bool = False
    has_san: bool = False
    san_count: int = 0
    has_wildcard_san: bool = False
    has_ip_san: bool = False
    matches_tested_hostname: bool | None = None
    is_ca: bool = False
    is_self_signed: bool = False
    chain_length: int = 1
    is_chain_complete: bool = False
    has_trusted_anchor: bool = False
    has_crl_distribution_points: bool = False
    has_ocsp_aia: bool = False
    has_scts: bool = False
    sct_count: int = 0
    is_cabf_validity_compliant: bool = False
    cabf_max_allowed_validity_days: float | None = None
    policy_applicability: str = "APPLICABLE"
    is_ca_constraint_compliant: bool = True
    is_eku_compliant: bool = True


class CertificateAnalyzeRequest(BaseModel):
    """Request payload for direct certificate evaluation."""

    hostname: str | None = Field(
        default=None,
        description="Target hostname for endpoint TLS handshake or certificate identity verification",
    )
    port: int = Field(default=443, ge=1, le=65535, description="Endpoint TLS destination port")
    pem: str | None = Field(
        default=None,
        description="Raw PEM certificate or multi-certificate bundle string",
    )
    include_ml_advisory: bool = Field(
        default=True,
        description="Whether to evaluate auxiliary ML compliance and anomaly advisory",
    )


class CertificateAssessmentResponse(BaseModel):
    """Complete digital trust intelligence assessment response."""

    certificate_sha256: str
    subject_dn: str
    issuer_dn: str
    verdict: str  # "TRUSTED", "WARNING", "DISTRUSTED", "INCONCLUSIVE"
    trust_score: int
    confidence: float
    scoring_version: str = "cert_v1.0.0"
    checks_completed: int = 6
    findings: list[FindingEvidenceItem] = Field(default_factory=list)
    features: dict[str, Any] = Field(default_factory=dict)
    policy_evaluation: dict[str, Any] | None = None
    ml_advisory: dict[str, Any] | None = None
    recommendations: list[str] = Field(default_factory=list)
    summary: str
    evaluated_at: str | None = None
