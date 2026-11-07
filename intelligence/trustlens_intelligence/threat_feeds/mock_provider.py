"""TrustLens Intelligence — Mock Threat Intelligence Provider.

Used for offline-first testing, simulation, and unit test fixtures.
"""

from datetime import datetime, timezone
import time
from typing import Any

from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider


class MockThreatProvider(ThreatIntelProvider):
    """Configurable mock threat intelligence provider for testing."""

    def __init__(
        self,
        name: str = "mock_provider",
        enabled: bool = True,
        simulate_timeout: bool = False,
        simulate_unavailable: bool = False,
        simulate_stale: bool = False,
        matches: set[str] | dict[str, dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(name=name, enabled=enabled, timeout_seconds=1.0)
        self.simulate_timeout = simulate_timeout
        self.simulate_unavailable = simulate_unavailable
        self.simulate_stale = simulate_stale
        self._matches: dict[str, dict[str, Any]] = {}

        if matches:
            if isinstance(matches, set):
                self._matches = {u.strip().lower(): {"status": "match", "matched": True} for u in matches}
            elif isinstance(matches, dict):
                self._matches = {k.strip().lower(): v for k, v in matches.items()}

    def add_match(self, url: str, details: dict[str, Any] | None = None) -> None:
        """Add a URL to match list."""
        self._matches[url.strip().lower()] = details or {"status": "match", "matched": True}

    def is_healthy(self) -> bool:
        return self.enabled and not self.simulate_unavailable and not self.simulate_stale

    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        """Execute mock query."""
        start = time.perf_counter()

        if not self.enabled:
            return self._create_result(
                status=ProviderResultStatus.NOT_CONFIGURED,
                details={"mock": True},
            )

        if self.simulate_timeout:
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                matched=False,
                details={"mock": True, "error": "timeout"},
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        if self.simulate_unavailable:
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                matched=False,
                details={"mock": True, "error": "service_unavailable"},
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        if self.simulate_stale:
            return self._create_result(
                status=ProviderResultStatus.STALE_CACHE,
                matched=False,
                details={"mock": True, "stale": True},
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        if is_sensitive and self.name == "urlhaus":
            return self._create_result(
                status=ProviderResultStatus.SKIPPED_SENSITIVE_URL,
                matched=False,
                details={"mock": True, "reason": "skipped_sensitive_url"},
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        url_key = url.strip().lower()
        if url_key in self._matches:
            match_info = self._matches[url_key]
            return self._create_result(
                status=ProviderResultStatus.MATCH,
                matched=True,
                details={"mock": True, **match_info},
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        return self._create_result(
            status=ProviderResultStatus.NO_MATCH,
            matched=False,
            details={"mock": True},
            latency_ms=(time.perf_counter() - start) * 1000,
        )

