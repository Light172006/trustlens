"""Common Pydantic models for standard error envelopes, health checks, and pagination."""

from datetime import UTC, datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Detailed validation or domain error item."""

    field: str = Field(..., description="Target field name or parameter")
    issue: str = Field(..., description="Description of the validation failure or issue")


class ErrorEnvelope(BaseModel):
    """Standardized error envelope payload."""

    code: str = Field(..., description="Machine-readable error identifier")
    message: str = Field(..., description="Human-readable error explanation")
    request_id: str = Field(..., description="Correlation request ID")
    details: list[ErrorDetail] = Field(
        default_factory=list, description="Array of specific validation/field issues"
    )


class ErrorResponse(BaseModel):
    """Top-level error response model."""

    error: ErrorEnvelope


class HealthCheckResponse(BaseModel):
    """Liveness and base health check response model."""

    status: str = Field(default="alive", description="Overall health state (alive, healthy)")
    service: str = Field(default="trustlens-api", description="Service identifier")
    version: str = Field(default="1.0.0", description="Application version")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    environment: str = Field(default="development", description="Current operating environment")


class DependencyHealthResponse(BaseModel):
    """Response model for individual service dependency probes."""

    status: str = Field(..., description="Dependency health state (healthy, unavailable)")
    dependency: str = Field(..., description="Name of the probed dependency (database, redis)")
    latency_ms: float | None = Field(None, description="Probe round-trip duration in milliseconds")
    message: str = Field(..., description="Safe status summary")


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination wrapper schema."""

    items: list[T] = Field(..., description="List of items for current page")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, le=100, description="Items per page")
    total: int = Field(..., ge=0, description="Total matching items across all pages")
    pages: int = Field(default=1, ge=1, description="Total pages available")

    model_config = ConfigDict(from_attributes=True)
