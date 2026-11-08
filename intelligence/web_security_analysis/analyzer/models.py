"""
TrustLens Web Security Analyzer - Data Models & Typed Schemas
Defines structured Pydantic schemas for analysis requests, security findings, and final reports.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityFindingModel(BaseModel):
    finding_id: str
    category: str
    name: str
    severity: str
    status: str
    evidence: str
    detection_method: str = "DETERMINISTIC_RULE_INSPECTION"
    confidence: float = 1.0
    guidance: Optional[str] = None
    recommendation: Optional[str] = None


class MLPredictionModel(BaseModel):
    available: bool = False
    predicted_posture: str
    probabilities: Dict[str, float] = Field(default_factory=dict)
    confidence: float = 0.0
    margin: Optional[float] = None
    abstained: bool = False
    abstention_reason: Optional[str] = None
    model_name: Optional[str] = None
    model_version: Optional[str] = None


class ConsensusModel(BaseModel):
    status: str
    discrepancy_explanation: Optional[str] = None


class FindingsSummaryModel(BaseModel):
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    pass_count: int
    affected_categories: List[str]


class RemediationItemModel(BaseModel):
    finding_id: str
    severity: str
    category: str
    recommendation: str


class WebSecurityReport(BaseModel):
    target_url: str
    normalized_domain: str
    registrable_domain: str
    scan_timestamp: str
    scanner_version: str = "1.0.0"
    posture: str
    security_score: float
    deterministic_posture: str
    ml_prediction: MLPredictionModel
    consensus: ConsensusModel
    findings_summary: FindingsSummaryModel
    findings: List[SecurityFindingModel]
    remediations: List[RemediationItemModel]
    telemetry: Dict[str, Any] = Field(default_factory=dict)

    def to_summary_text(self) -> str:
        """Renders a clean human-readable executive summary."""
        lines = [
            f"============================================================",
            f"TrustLens Web Security Assessment: {self.target_url}",
            f"============================================================",
            f"Normalized Domain:    {self.normalized_domain} (Registrable: {self.registrable_domain})",
            f"Scan Timestamp:       {self.scan_timestamp}",
            f"Security Posture:     {self.posture}",
            f"Security Score:       {self.security_score}/100",
            f"ML Predicted Class:   {self.ml_prediction.predicted_posture} (Confidence: {self.ml_prediction.confidence:.2f})",
            f"Consensus Status:     {self.consensus.status}",
        ]
        if self.consensus.discrepancy_explanation:
            lines.append(f"Consensus Note:       {self.consensus.discrepancy_explanation}")

        lines.extend([
            f"------------------------------------------------------------",
            f"Findings Breakdown:   CRITICAL: {self.findings_summary.critical_count} | "
            f"HIGH: {self.findings_summary.high_count} | MEDIUM: {self.findings_summary.medium_count} | "
            f"LOW: {self.findings_summary.low_count} | PASS: {self.findings_summary.pass_count}",
            f"Affected Categories:  {', '.join(self.findings_summary.affected_categories) or 'None'}",
            f"------------------------------------------------------------",
        ])

        if self.remediations:
            lines.append("Prioritized Remediation Actions:")
            for i, r in enumerate(self.remediations[:8], start=1):
                lines.append(f"  {i}. [{r.severity}] {r.finding_id}: {r.recommendation}")
        else:
            lines.append("No active vulnerabilities or remediation actions required.")

        lines.append("============================================================")
        return "\n".join(lines)

