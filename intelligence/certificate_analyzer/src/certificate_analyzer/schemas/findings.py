"""Findings schemas for Certificate Analyzer."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from certificate_analyzer.constants import FindingSeverity


class CertificateFinding(BaseModel):
    """Structured finding detailing a certificate or TLS defect, warning, or positive trust factor."""

    code: str = Field(..., description="Unique machine-readable finding code (e.g. 'RULE_EXPIRED')")
    title: str = Field(..., description="Human-readable title")
    severity: FindingSeverity = Field(..., description="Severity classification")
    description: str = Field(..., description="Detailed technical explanation of the finding")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="Observed cryptographic or temporal evidence")
    recommendation: Optional[str] = Field(default=None, description="Actionable remediation advice for PKI administrators")
    score_deduction: int = Field(default=0, ge=0, le=100, description="Points deducted from base trust score")

