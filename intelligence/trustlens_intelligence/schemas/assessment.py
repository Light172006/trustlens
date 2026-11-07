"""TrustLens Intelligence — Threat Assessment and Evaluation Output Schemas."""

from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field

from trustlens_intelligence.config.constants import CURRENT_SCORING_VERSION, LayerCoverage, Verdict
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult


class MLPrediction(BaseModel):
    """Machine learning model inference result."""

    model_name: str = Field(..., description="Name of the model (e.g., 'random_forest_baseline')")
    model_version: str = Field(..., description="Model version")
    malicious_probability: float = Field(..., ge=0.0, le=1.0, description="Predicted probability of maliciousness")
    predicted_label: str = Field(..., description="'legitimate', 'suspicious', or 'malicious'")
    calibrated_confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated prediction confidence")
    top_contributing_features: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Features that contributed most strongly to this prediction",
    )


class ThreatAssessment(BaseModel):
    """Authoritative threat intelligence assessment produced by the intelligence engine."""

    scan_id: str = Field(default="", description="Scan ID")
    verdict: Verdict = Field(..., description="Overall verdict (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)")
    risk_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Deterministic risk score 0-100; null if inconclusive/failed without reliable score",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the assessment based on evidence coverage and quality",
    )
    scoring_version: str = Field(default=CURRENT_SCORING_VERSION, description="Version of the scoring algorithm")
    checks_completed: int = Field(default=0, ge=0, description="Number of analysis checks completed")
    coverage: dict[str, LayerCoverage | str] = Field(
        default_factory=dict,
        description="Status of analysis layers: threat_intel, web_security, certificate, community",
    )
    findings: list[Finding] = Field(default_factory=list, description="Ordered list of findings")
    provider_checks: list[ProviderCheckResult] = Field(
        default_factory=list,
        description="Results of querying intelligence providers",
    )
    features: ExtractedFeatures | None = Field(default=None, description="Extracted feature vector")
    ml_prediction: MLPrediction | None = Field(default=None, description="Optional ML classification signal")
    summary: str = Field(..., description="Human-readable executive summary of the assessment")
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of evaluation",
    )

    def to_api_dict(self) -> dict[str, Any]:
        """Convert assessment into format matching API.md and PRD.md contracts."""
        return {
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 2),
            "scoring_version": self.scoring_version,
            "checks_completed": self.checks_completed,
            "coverage": {k: (v.value if isinstance(v, LayerCoverage) else str(v)) for k, v in self.coverage.items()},
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "provider_checks": [p.model_dump(mode="json") for p in self.provider_checks],
            "summary": self.summary,
            "evaluated_at": self.evaluated_at.isoformat(),
        }

