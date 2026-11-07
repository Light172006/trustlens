"""TrustLens Intelligence — Threat Feed Provider Base Class."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
from typing import Any
import httpx

from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.schemas.providers import ProviderCheckResult

logger = logging.getLogger("trustlens.intelligence.threat_feeds")


class ThreatIntelProvider(ABC):
    """Abstract base class for all threat intelligence adapters."""

    def __init__(self, name: str, enabled: bool = True, timeout_seconds: float = 5.0) -> None:
        self.name = name
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.last_check_time: datetime | None = None
        self.last_successful_sync: datetime | None = None
        self._consecutive_errors: int = 0

    @abstractmethod
    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        """Query provider for threat status on the given canonical URL.

        Args:
            url: The canonical URL to inspect.
            is_sensitive: If True, indicates URL contains sensitive tokens and must not
                be transmitted to external per-URL lookup endpoints.

        Returns:
            ProviderCheckResult with normalized status and details.
        """
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check whether the provider is operational and within freshness limits."""
        pass

    def _create_result(
        self,
        status: ProviderResultStatus,
        matched: bool = False,
        details: dict[str, Any] | None = None,
        latency_ms: float | None = None,
    ) -> ProviderCheckResult:
        """Helper to build a standardized ProviderCheckResult."""
        return ProviderCheckResult(
            provider=self.name,
            result_status=status,
            matched=matched,
            details=details or {},
            checked_at=datetime.now(timezone.utc),
            latency_ms=latency_ms,
        )

