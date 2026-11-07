"""TrustLens Intelligence — URLhaus Malware Provider Adapter.

Queries the URLhaus API for malware distribution intelligence.
Respects sensitive URL privacy policies by never transmitting sensitive URLs.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any
import httpx

from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider

logger = logging.getLogger("trustlens.intelligence.threat_feeds.urlhaus")


class URLhausProvider(ThreatIntelProvider):
    """Adapter for the abuse.ch URLhaus malware database API."""

    def __init__(
        self,
        enabled: bool = True,
        api_url: str = "https://urlhaus-api.abuse.ch/v1/url/",
        auth_key: str | None = None,
        timeout_seconds: float = 4.0,
        max_retries: int = 2,
        backoff_factor: float = 0.5,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(name="urlhaus", enabled=enabled, timeout_seconds=timeout_seconds)
        self.api_url = api_url
        self.auth_key = auth_key
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._client = http_client

    def is_healthy(self) -> bool:
        """Provider is considered healthy if enabled and consecutive errors < 3."""
        return self.enabled and self._consecutive_errors < 3

    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        """Query URLhaus for the submitted URL."""
        start_time = time.perf_counter()

        if not self.enabled:
            return self._create_result(
                status=ProviderResultStatus.NOT_CONFIGURED,
                details={"reason": "URLhaus provider disabled"},
            )

        # Privacy gate: never send sensitive URLs containing potential tokens/secrets
        if is_sensitive:
            logger.info("Skipping URLhaus lookup because URL is flagged as sensitive")
            return self._create_result(
                status=ProviderResultStatus.SKIPPED_SENSITIVE_URL,
                matched=False,
                details={"reason": "Skipped to prevent disclosure of sensitive URL query parameters"},
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        headers: dict[str, str] = {
            "User-Agent": "TrustLens-Intelligence/1.0",
            "Accept": "application/json",
        }
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=self.timeout_seconds)

        response = None
        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                response = client.post(
                    self.api_url,
                    data={"url": url.strip()},
                    headers=headers,
                )
                if response.status_code in (502, 503, 504) and attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2**attempt))
                    continue
                response.raise_for_status()
                last_exception = None
                break
            except httpx.TimeoutException as exc:
                last_exception = exc
                break  # Do not retry on timeout
            except (httpx.NetworkError, httpx.RemoteProtocolError) as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    time.sleep(self.backoff_factor * (2**attempt))
                    continue
                break
            except Exception as exc:
                last_exception = exc
                break

        try:
            if last_exception is not None:
                raise last_exception
            if response is None:
                raise RuntimeError("No HTTP response received from URLhaus")

            data = response.json()
            latency = (time.perf_counter() - start_time) * 1000
            self._consecutive_errors = 0
            self.last_check_time = datetime.now(timezone.utc)

            query_status = data.get("query_status")

            if query_status == "ok":
                url_status = str(data.get("url_status", "unknown")).lower()
                threat = data.get("threat", "malware_download")
                tags = data.get("tags") or []
                date_added = data.get("date_added")

                # Both online and offline count as matches in provider check,
                # but scoring distinguishes online (decisive 100) vs offline (historical 25).
                return self._create_result(
                    status=ProviderResultStatus.MATCH,
                    matched=True,
                    details={
                        "query_status": query_status,
                        "url_status": url_status,
                        "threat": threat,
                        "tags": tags,
                        "date_added": date_added,
                    },
                    latency_ms=latency,
                )

            if query_status == "no_results":
                return self._create_result(
                    status=ProviderResultStatus.NO_MATCH,
                    matched=False,
                    details={"query_status": query_status},
                    latency_ms=latency,
                )

            # Unexpected query_status (e.g. rate-limit, invalid format)
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                matched=False,
                details={"query_status": query_status, "message": data.get("message")},
                latency_ms=latency,
            )

        except httpx.TimeoutException:
            self._consecutive_errors += 1
            latency = (time.perf_counter() - start_time) * 1000
            logger.warning("URLhaus query timed out after %.1fs", self.timeout_seconds)
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                matched=False,
                details={"error": "timeout", "timeout_seconds": self.timeout_seconds},
                latency_ms=latency,
            )
        except Exception as exc:
            self._consecutive_errors += 1
            latency = (time.perf_counter() - start_time) * 1000
            # Redact any accidental credential leak from exception message
            sanitized_err = str(exc).split("?")[0]
            logger.warning("URLhaus query failed: %s", sanitized_err)
            return self._create_result(
                status=ProviderResultStatus.UNAVAILABLE,
                matched=False,
                details={"error": "request_failed", "error_type": type(exc).__name__},
                latency_ms=latency,
            )
        finally:
            if owns_client:
                client.close()

