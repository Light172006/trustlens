"""TrustLens Intelligence — OpenPhish Feed Provider Adapter.

Operates as a local indicator cache fed by the OpenPhish community feed.
Because it evaluates against a local cache, checking URLs (even sensitive ones)
does not transmit the target URL across the network.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any
from urllib.parse import urlparse, urlunparse
import httpx

from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.common.url_utils import canonicalize_url_strict
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider

logger = logging.getLogger("trustlens.intelligence.threat_feeds.openphish")


def canonicalize_url(url: str) -> str:
    """Normalize URL for consistent exact indicator matching."""
    return canonicalize_url_strict(url)


class OpenPhishProvider(ThreatIntelProvider):
    """Adapter for OpenPhish community feed."""

    def __init__(
        self,
        enabled: bool = True,
        feed_url: str = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        max_age_hours: float = 13.0,
        timeout_seconds: float = 5.0,
        initial_indicators: set[str] | None = None,
    ) -> None:
        super().__init__(name="openphish", enabled=enabled, timeout_seconds=timeout_seconds)
        self.feed_url = feed_url
        self.max_age_hours = max_age_hours
        self._indicators: set[str] = set()
        if initial_indicators:
            self.load_indicators(initial_indicators)

    def load_indicators(self, indicators: set[str] | list[str]) -> None:
        """Load indicators directly (useful for local fixtures or backend sync)."""
        self._indicators = {canonicalize_url(u) for u in indicators if u and u.strip()}
        self.last_successful_sync = datetime.now(timezone.utc)
        self._consecutive_errors = 0
        logger.info("OpenPhish loaded %d indicators into local cache", len(self._indicators))

    def sync_feed(self, client: httpx.Client | None = None) -> bool:
        """Download and ingest the latest community feed from OpenPhish."""
        if not self.enabled:
            return False

        start_time = time.perf_counter()
        owns_client = client is None
        http_client = client or httpx.Client(timeout=self.timeout_seconds)

        try:
            response = http_client.get(self.feed_url)
            response.raise_for_status()
            lines = response.text.splitlines()
            parsed_urls = {canonicalize_url(line) for line in lines if line.strip() and not line.startswith("#")}

            self._indicators = parsed_urls
            self.last_successful_sync = datetime.now(timezone.utc)
            self._consecutive_errors = 0
            duration = (time.perf_counter() - start_time) * 1000
            logger.info("OpenPhish sync successful: %d indicators in %.1fms", len(self._indicators), duration)
            return True
        except Exception as exc:
            self._consecutive_errors += 1
            logger.warning("OpenPhish feed sync failed (error #%d): %s", self._consecutive_errors, exc)
            return False
        finally:
            if owns_client:
                http_client.close()

    def is_stale(self) -> bool:
        """Return True if the feed hasn't synced within the maximum allowed age."""
        if not self.last_successful_sync:
            return True
        age_hours = (datetime.now(timezone.utc) - self.last_successful_sync).total_seconds() / 3600.0
        return age_hours > self.max_age_hours

    def is_healthy(self) -> bool:
        """Provider is healthy if enabled, has indicators, and is not stale."""
        return self.enabled and bool(self._indicators) and not self.is_stale()

    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        """Query URL against local OpenPhish indicator store."""
        start_time = time.perf_counter()

        if not self.enabled:
            return self._create_result(
                status=ProviderResultStatus.NOT_CONFIGURED,
                details={"reason": "OpenPhish provider disabled"},
            )

        if not self.last_successful_sync and not self._indicators:
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                details={"reason": "OpenPhish feed not yet synchronized"},
            )

        # Check freshness
        if self.is_stale():
            age_hours = (
                (datetime.now(timezone.utc) - self.last_successful_sync).total_seconds() / 3600.0
                if self.last_successful_sync
                else 999.0
            )
            # Stale feed cannot produce a clean no-match
            norm_url = canonicalize_url(url)
            matched = norm_url in self._indicators
            latency = (time.perf_counter() - start_time) * 1000
            if matched:
                return self._create_result(
                    status=ProviderResultStatus.MATCH,
                    matched=True,
                    details={"feed_age_hours": round(age_hours, 1), "stale_warning": True},
                    latency_ms=latency,
                )
            return self._create_result(
                status=ProviderResultStatus.STALE_CACHE,
                matched=False,
                details={"feed_age_hours": round(age_hours, 1), "max_age_hours": self.max_age_hours},
                latency_ms=latency,
            )

        norm_url = canonicalize_url(url)
        matched = norm_url in self._indicators
        latency = (time.perf_counter() - start_time) * 1000

        if matched:
            return self._create_result(
                status=ProviderResultStatus.MATCH,
                matched=True,
                details={
                    "indicator_type": "url",
                    "feed_source": "openphish_community",
                    "feed_size": len(self._indicators),
                    "last_sync": self.last_successful_sync.isoformat() if self.last_successful_sync else None,
                },
                latency_ms=latency,
            )

        return self._create_result(
            status=ProviderResultStatus.NO_MATCH,
            matched=False,
            details={
                "feed_source": "openphish_community",
                "feed_size": len(self._indicators),
                "last_sync": self.last_successful_sync.isoformat() if self.last_successful_sync else None,
            },
            latency_ms=latency,
        )

