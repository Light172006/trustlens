"""TrustLens Intelligence — Community Intelligence Adapter.

Interprets community-submitted threat reports and moderator validations.
Strictly enforces the rule that unmoderated submissions and single reports
cannot label a website as malicious.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any

from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider

logger = logging.getLogger("trustlens.intelligence.threat_feeds.community")


class CommunityIntelProvider(ThreatIntelProvider):
    """Adapter for TrustLens community-verified indicators and reports."""

    def __init__(
        self,
        enabled: bool = True,
        initial_reports: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        super().__init__(name="community", enabled=enabled, timeout_seconds=1.0)
        # Mapping canonical_url -> list of confirmed reports with reporter IDs
        self._reports_by_url: dict[str, list[dict[str, Any]]] = initial_reports or {}

    def is_healthy(self) -> bool:
        """Community provider is always locally available."""
        return self.enabled

    def register_report(
        self,
        canonical_url: str,
        reporter_id: str,
        status: str = "confirmed",
        category: str = "phishing",
        evidence_text: str = "",
    ) -> None:
        """Register a report for testing or offline ingestion."""
        url_key = canonical_url.strip().lower()
        if url_key not in self._reports_by_url:
            self._reports_by_url[url_key] = []

        self._reports_by_url[url_key].append(
            {
                "reporter_id": reporter_id,
                "status": status,
                "category": category,
                "evidence_text": evidence_text,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        """Query community reports for the canonical URL."""
        start_time = time.perf_counter()

        if not self.enabled:
            return self._create_result(
                status=ProviderResultStatus.NOT_CONFIGURED,
                details={"reason": "Community provider disabled"},
            )

        url_key = url.strip().lower()
        reports = self._reports_by_url.get(url_key, [])
        confirmed_reports = [r for r in reports if r.get("status") == "confirmed"]

        distinct_reporters = {r.get("reporter_id") for r in confirmed_reports if r.get("reporter_id")}
        distinct_count = len(distinct_reporters)
        confirmed_count = len(confirmed_reports)

        latency = (time.perf_counter() - start_time) * 1000

        # PRD rule: At least two moderator-confirmed reports from distinct reporter accounts
        # are required for a decisive malicious community match.
        if confirmed_count >= 2 and distinct_count >= 2:
            return self._create_result(
                status=ProviderResultStatus.MATCH,
                matched=True,
                details={
                    "confirmed_reports_count": confirmed_count,
                    "distinct_reporters_count": distinct_count,
                    "is_decisive": True,
                    "categories": list({r.get("category", "other") for r in confirmed_reports}),
                },
                latency_ms=latency,
            )

        if confirmed_count >= 1:
            # 1 confirmed report: recorded as informational, but not decisive
            return self._create_result(
                status=ProviderResultStatus.MATCH,
                matched=False,
                details={
                    "confirmed_reports_count": confirmed_count,
                    "distinct_reporters_count": distinct_count,
                    "is_decisive": False,
                    "note": "Single confirmed community report is non-authoritative without secondary confirmation",
                },
                latency_ms=latency,
            )

        return self._create_result(
            status=ProviderResultStatus.NO_MATCH,
            matched=False,
            details={"confirmed_reports_count": 0, "distinct_reporters_count": 0},
            latency_ms=latency,
        )

