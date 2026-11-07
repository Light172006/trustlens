"""Redirect scanner enforcing hop-by-hop SSRF validation, hop limits, and loop detection."""

from pydantic import BaseModel, Field

from app.config import settings
from app.core.exceptions import TrustLensException
from app.scanners.url_validator import validate_and_canonicalize_url


class RedirectHop(BaseModel):
    """Normalized observation for an individual redirect hop."""

    hop_index: int
    source_url: str
    destination_url: str
    http_status: int
    resolved_host: str
    resolved_ips: list[str] = Field(default_factory=list)
    tls_verified: bool = False


class RedirectScanResult(BaseModel):
    """Aggregate redirect traversal result."""

    hops: list[RedirectHop] = Field(default_factory=list)
    final_url: str
    redirect_count: int = 0
    http_to_https_redirect: bool = False
    loop_detected: bool = False
    exceeded_max_hops: bool = False
    error: str | None = None


class RedirectTracker:
    """Manages safe redirect traversal with mandatory revalidation."""

    def __init__(self, max_redirects: int = 5) -> None:
        self.max_redirects = min(max_redirects, settings.SCAN_MAX_REDIRECTS)

    def validate_next_hop(
        self,
        current_url: str,
        location_header: str,
        seen_urls: list[str],
        allow_private_for_tests: bool = False,
    ) -> str:
        """Validate destination URL from Location header against SSRF and loops."""
        from urllib.parse import urljoin

        # Resolve relative URLs against current URL
        next_url = urljoin(current_url, location_header.strip())

        # Check for redirect loop
        if next_url in seen_urls:
            raise TrustLensException(
                message=f"Redirect loop detected targeting '{next_url}'.",
                code="REDIRECT_LOOP_DETECTED",
                status_code=400,
            )

        # Validate next hop against SSRF rules (DNS resolution and IP checks)
        target = validate_and_canonicalize_url(
            raw_url=next_url,
            allow_private_for_tests=allow_private_for_tests,
        )

        return target.canonical_url


redirect_tracker = RedirectTracker()
