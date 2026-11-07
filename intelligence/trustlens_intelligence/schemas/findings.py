"""TrustLens Intelligence — Finding and Rule Match Schemas."""

from datetime import datetime, timezone
from typing import Any
import uuid
from pydantic import BaseModel, Field

from trustlens_intelligence.config.constants import FindingCategory, FindingSeverity


class Finding(BaseModel):
    """A structured finding representing an evaluated risk or security observation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Finding UUID")
    code: str = Field(..., description="Stable rule identifier (e.g., CERT_EXPIRED, CSP_MISSING)")
    category: FindingCategory = Field(..., description="Finding category")
    title: str = Field(..., description="Short human-readable finding title")
    description: str = Field(..., description="Detailed description referencing actual observations")
    severity: FindingSeverity = Field(..., description="Finding severity level")
    points: int = Field(default=0, ge=0, le=100, description="Risk point contribution (0-100)")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Observed facts that triggered the finding")
    remediation: str = Field(..., description="Actionable recommendation or safety guidance")
    source: str = Field(..., description="Attribution / rule engine source")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Detection timestamp",
    )

