"""TrustLens Intelligence — Threat Intelligence Feed Manager.

Coordinates provider queries, manages in-memory caching, evaluates coverage,
and ensures that missing or failed threat intelligence queries are never
interpreted as clean negative matches.
"""

from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any

from trustlens_intelligence.common.url_utils import canonicalize_url_strict
from trustlens_intelligence.config.constants import LayerCoverage, ProviderName, ProviderResultStatus
from trustlens_intelligence.config.settings import ThreatFeedSettings
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider
from trustlens_intelligence.threat_feeds.community import CommunityIntelProvider
from trustlens_intelligence.threat_feeds.openphish import OpenPhishProvider
from trustlens_intelligence.threat_feeds.urlhaus import URLhausProvider

logger = logging.getLogger("trustlens.intelligence.threat_feeds.manager")


class ThreatIntelManager:
    """Orchestrates threat intelligence lookups across registered providers."""

    def __init__(
        self,
        settings: ThreatFeedSettings | None = None,
        providers: list[ThreatIntelProvider] | None = None,
    ) -> None:
        self.settings = settings or ThreatFeedSettings()
        self._providers: dict[str, ThreatIntelProvider] = {}
        # Cache entries: (provider_name, url) -> (ProviderCheckResult, expire_timestamp)
        self._cache: dict[tuple[str, str], tuple[ProviderCheckResult, float]] = {}
        self._lock = threading.Lock()
        self.max_cache_size = self.settings.max_cache_size

        if providers:
            for p in providers:
                self.register_provider(p)
        else:
            # Register standard default providers
            self.register_provider(
                OpenPhishProvider(
                    enabled=self.settings.openphish_enabled,
                    feed_url=self.settings.openphish_feed_url,
                    max_age_hours=self.settings.openphish_max_age_hours,
                    timeout_seconds=self.settings.openphish_request_timeout_seconds,
                )
            )
            self.register_provider(
                URLhausProvider(
                    enabled=self.settings.urlhaus_enabled,
                    api_url=self.settings.urlhaus_api_url,
                    auth_key=self.settings.urlhaus_auth_key,
                    timeout_seconds=self.settings.urlhaus_request_timeout_seconds,
                )
            )
            self.register_provider(CommunityIntelProvider())

    def register_provider(self, provider: ThreatIntelProvider) -> None:
        """Register or override a threat intelligence provider."""
        self._providers[provider.name] = provider
        logger.info("Registered threat provider: %s", provider.name)

    def get_provider(self, name: str) -> ThreatIntelProvider | None:
        """Retrieve a registered provider by name."""
        return self._providers.get(name)

    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        with self._lock:
            self._cache.clear()

    def _evict_if_needed(self, now: float) -> None:
        """Evict expired items, and if still over max_cache_size, evict oldest items."""
        if len(self._cache) < self.max_cache_size:
            return

        # 1. Purge expired entries
        expired_keys = [k for k, (_, exp) in self._cache.items() if now >= exp]
        for k in expired_keys:
            self._cache.pop(k, None)

        # 2. If still at or over capacity, evict oldest 10% of entries
        if len(self._cache) >= self.max_cache_size:
            to_remove = max(1, len(self._cache) // 10)
            oldest_keys = list(self._cache.keys())[:to_remove]
            for k in oldest_keys:
                self._cache.pop(k, None)

    def query_all(
        self,
        url: str,
        is_sensitive: bool = False,
        use_cache: bool = True,
    ) -> list[ProviderCheckResult]:
        """Query all registered providers for the given URL.

        Args:
            url: Canonical URL to evaluate.
            is_sensitive: Flag indicating URL contains sensitive query parameters.
            use_cache: Whether to check and update the in-memory TTL cache.

        Returns:
            List of ProviderCheckResult objects from all providers.
        """
        results: list[ProviderCheckResult] = []
        now = time.time()
        ttl = self.settings.provider_cache_ttl_seconds
        canonical_target = canonicalize_url_strict(url) if url else ""

        for name, provider in self._providers.items():
            cache_key = (name, canonical_target, is_sensitive)

            if use_cache:
                with self._lock:
                    if cache_key in self._cache:
                        cached_res, expire_time = self._cache[cache_key]
                        if now < expire_time:
                            results.append(cached_res)
                            continue

            try:
                res = provider.query(url, is_sensitive=is_sensitive)
            except Exception as exc:
                logger.error("Provider %s threw unhandled exception: %s", name, exc)
                res = ProviderCheckResult(
                    provider=name,
                    result_status=ProviderResultStatus.UNAVAILABLE,
                    matched=False,
                    details={"error": "unhandled_provider_exception", "type": type(exc).__name__},
                    checked_at=datetime.now(timezone.utc),
                )

            if use_cache:
                with self._lock:
                    self._evict_if_needed(now)
                    self._cache[cache_key] = (res, now + ttl)

            results.append(res)

        return results

    @staticmethod
    def evaluate_threat_coverage(results: list[ProviderCheckResult]) -> LayerCoverage:
        """Evaluate the overall coverage status of the threat intelligence layer.

        Rule from PRD FR-09:
        Clean SAFE verdict requires fresh successful phishing and malware feed coverage.
        If any required feed is unavailable, stale, or skipped, coverage cannot be COMPLETE.
        """
        if not results:
            return LayerCoverage.UNAVAILABLE

        status_by_provider = {r.provider: r.result_status for r in results}

        # Check required providers: OpenPhish (phishing) and URLhaus (malware)
        openphish_status = status_by_provider.get(ProviderName.OPENPHISH.value)
        urlhaus_status = status_by_provider.get(ProviderName.URLHAUS.value)

        # If both are valid results (either match or verified no_match)
        valid_statuses = {ProviderResultStatus.MATCH, ProviderResultStatus.NO_MATCH}

        if openphish_status in valid_statuses and urlhaus_status in valid_statuses:
            return LayerCoverage.COMPLETE

        # If at least one produced a match, it is usable for detection but coverage remains partial
        if any(r.matched for r in results):
            return LayerCoverage.PARTIAL

        # If any required provider is unavailable, stale, or skipped
        problematic_statuses = {
            ProviderResultStatus.UNAVAILABLE,
            ProviderResultStatus.STALE_CACHE,
            ProviderResultStatus.SKIPPED_SENSITIVE_URL,
            ProviderResultStatus.NOT_CONFIGURED,
        }

        if openphish_status in problematic_statuses or urlhaus_status in problematic_statuses:
            return LayerCoverage.PARTIAL

        return LayerCoverage.PARTIAL

