"""Bounded, safe HTTP website scanner with manual redirect following and header inspection."""

import time

import httpx
from pydantic import BaseModel

from app.config import settings
from app.core.exceptions import TrustLensException
from app.scanners.redirect_scanner import RedirectHop, RedirectScanResult, redirect_tracker
from app.scanners.security_headers import (
    CookieObservation,
    SecurityHeadersResult,
    security_header_scanner,
)
from app.scanners.url_validator import ValidatedTarget


class HttpScanResult(BaseModel):
    """Aggregate HTTP layer inspection observations."""

    initial_url: str
    final_url: str
    status_code: int | None = None
    response_time_ms: float = 0.0
    content_type: str | None = None
    content_length: int | None = None
    redirects: RedirectScanResult
    security_headers: SecurityHeadersResult
    connection_failed: bool = False
    error_message: str | None = None
    completed: bool = False


class HttpScanner:
    """Performs bounded passive HTTP fetches and manual redirect validation."""

    def __init__(self) -> None:
        self.max_redirects = settings.SCAN_MAX_REDIRECTS
        self.max_body_bytes = settings.SCAN_MAX_BODY_BYTES
        self.connect_timeout = float(settings.SCAN_CONNECT_TIMEOUT_SECONDS)
        self.total_timeout = float(settings.SCAN_TIMEOUT_SECONDS)

    async def scan(
        self,
        target: ValidatedTarget,
        allow_private_for_tests: bool = False,
    ) -> HttpScanResult:
        """Execute bounded HTTP GET request following redirects safely."""
        start_total = time.monotonic()
        current_url = target.canonical_url
        seen_urls: list[str] = [current_url]
        redirect_hops: list[RedirectHop] = []

        last_status: int | None = None
        last_headers: dict[str, str] = {}
        observed_cookies: list[CookieObservation] = []
        content_type: str | None = None
        content_length: int | None = None
        http_to_https = False
        final_url = current_url
        error_msg: str | None = None
        conn_failed = False

        headers = {
            "User-Agent": "TrustLens-Scanner/1.0 (+https://trustlens.internal/scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        transport = httpx.AsyncHTTPTransport(retries=0)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(self.total_timeout, connect=self.connect_timeout),
            follow_redirects=False,
            verify=True,
        ) as client:
            hop_count = 0

            while hop_count <= self.max_redirects:
                try:
                    response = await client.get(current_url, headers=headers)
                    last_status = response.status_code
                    last_headers = dict(response.headers)
                    content_type = last_headers.get("content-type")

                    # Extract cookies
                    for name, _value in response.cookies.items():
                        # Parse Set-Cookie header attributes if available
                        raw_set_cookie = last_headers.get("set-cookie", "")
                        is_sec = "secure" in raw_set_cookie.lower()
                        is_http = "httponly" in raw_set_cookie.lower()
                        samesite = None
                        if "samesite=strict" in raw_set_cookie.lower():
                            samesite = "strict"
                        elif "samesite=lax" in raw_set_cookie.lower():
                            samesite = "lax"
                        elif "samesite=none" in raw_set_cookie.lower():
                            samesite = "none"

                        observed_cookies.append(
                            CookieObservation(
                                name=name,
                                secure=is_sec,
                                httponly=is_http,
                                samesite=samesite,
                            )
                        )

                    # Check for redirect status
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            break

                        hop_count += 1
                        # Revalidate destination against SSRF
                        try:
                            next_url = redirect_tracker.validate_next_hop(
                                current_url=current_url,
                                location_header=location,
                                seen_urls=seen_urls,
                                allow_private_for_tests=allow_private_for_tests,
                            )
                        except TrustLensException as exc:
                            error_msg = f"Redirect blocked: {exc.message}"
                            break

                        if current_url.startswith("http://") and next_url.startswith("https://"):
                            http_to_https = True

                        redirect_hops.append(
                            RedirectHop(
                                hop_index=hop_count - 1,
                                source_url=current_url,
                                destination_url=next_url,
                                http_status=response.status_code,
                                resolved_host=target.host,
                                resolved_ips=target.resolved_ips,
                                tls_verified=current_url.startswith("https://"),
                            )
                        )

                        seen_urls.append(next_url)
                        current_url = next_url
                        final_url = next_url
                        continue

                    # Terminal response reached
                    final_url = current_url
                    # Bounded content reading (up to max_body_bytes)
                    content_length = len(response.content[: self.max_body_bytes])
                    break

                except httpx.ConnectTimeout:
                    conn_failed = True
                    error_msg = "Connection timed out"
                    break
                except httpx.ConnectError as exc:
                    conn_failed = True
                    error_msg = f"Connection failed: {exc}"
                    break
                except Exception as exc:
                    conn_failed = True
                    error_msg = f"HTTP request failed: {type(exc).__name__}"
                    break

        elapsed_ms = round((time.monotonic() - start_total) * 1000, 2)

        redirect_result = RedirectScanResult(
            hops=redirect_hops,
            final_url=final_url,
            redirect_count=len(redirect_hops),
            http_to_https_redirect=http_to_https,
            exceeded_max_hops=hop_count > self.max_redirects,
            error=error_msg if hop_count > self.max_redirects else None,
        )

        # Analyze security headers from terminal response
        is_https_final = final_url.startswith("https://")
        header_result = security_header_scanner.analyze(
            headers=last_headers,
            cookies=observed_cookies,
            is_https=is_https_final,
        )

        return HttpScanResult(
            initial_url=target.canonical_url,
            final_url=final_url,
            status_code=last_status,
            response_time_ms=elapsed_ms,
            content_type=content_type,
            content_length=content_length,
            redirects=redirect_result,
            security_headers=header_result,
            connection_failed=conn_failed,
            error_message=error_msg,
            completed=not conn_failed and last_status is not None,
        )


http_scanner = HttpScanner()
