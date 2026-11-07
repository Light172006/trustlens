"""TrustLens Intelligence — Threat Intelligence Provider Schemas."""

from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel, Field

from trustlens_intelligence.config.constants import ProviderResultStatus


class ProviderCheckResult(BaseModel):
    """Normalized result of querying an external or local threat intelligence provider."""

    provider: str = Field(..., description="Provider name (openphish, urlhaus, community)")
    result_status: ProviderResultStatus = Field(
        ...,
        description="Standardized result status (match, no_match, unavailable, etc.)",
    )
    matched: bool = Field(default=False, description="True only if an active malicious match was verified")
    details: dict[str, Any] = Field(default_factory=dict, description="Provider-specific facts and metadata")
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the query",
    )
    latency_ms: float | None = Field(default=None, description="Query latency in milliseconds")

