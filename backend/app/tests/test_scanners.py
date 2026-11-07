"""Automated tests for URL validation, SSRF protection, DNS, HTTP, TLS, and header scanners."""

import pytest

from app.core.exceptions import (
    TargetNotPublicException,
    TrustLensException,
)
from app.scanners.redirect_scanner import redirect_tracker
from app.scanners.security_headers import security_header_scanner
from app.scanners.url_validator import (
    detect_sensitive_url,
    is_ip_globally_routable,
    validate_and_canonicalize_url,
)


def test_ip_globally_routable_classification() -> None:
    """Verify IP classification correctly distinguishes public from private/reserved addresses."""
    # Prohibited addresses
    assert is_ip_globally_routable("127.0.0.1") is False
    assert is_ip_globally_routable("10.0.0.1") is False
    assert is_ip_globally_routable("192.168.1.1") is False
    assert is_ip_globally_routable("172.16.0.1") is False
    assert is_ip_globally_routable("169.254.169.254") is False
    assert is_ip_globally_routable("0.0.0.0") is False
    assert is_ip_globally_routable("::1") is False
    assert is_ip_globally_routable("fe80::1") is False
    assert is_ip_globally_routable("::ffff:127.0.0.1") is False
    assert is_ip_globally_routable("::ffff:169.254.169.254") is False

    # Allowed public addresses
    assert is_ip_globally_routable("8.8.8.8") is True
    assert is_ip_globally_routable("1.1.1.1") is True
    assert is_ip_globally_routable("93.184.216.34") is True
    assert is_ip_globally_routable("2606:4700:4700::1111") is True


def test_validate_unsupported_schemes_rejected() -> None:
    """Verify rejection of non-HTTP schemes."""
    for scheme in (
        "ftp://example.com",
        "file:///etc/passwd",
        "gopher://example.com",
        "javascript:alert(1)",
    ):
        with pytest.raises(TrustLensException) as exc_info:
            validate_and_canonicalize_url(scheme)
        assert exc_info.value.code == "UNSUPPORTED_URL_SCHEME"


def test_validate_credentials_in_url_rejected() -> None:
    """Verify rejection of embedded user credentials."""
    with pytest.raises(TrustLensException) as exc_info:
        validate_and_canonicalize_url("https://admin:secret@example.com")
    assert exc_info.value.code == "CREDENTIALS_IN_URL_REJECTED"


def test_validate_localhost_and_private_ip_rejected() -> None:
    """Verify SSRF protection blocks localhost and private IPs."""
    with pytest.raises(TargetNotPublicException):
        validate_and_canonicalize_url("http://localhost")

    with pytest.raises(TargetNotPublicException):
        validate_and_canonicalize_url("http://127.0.0.1")

    with pytest.raises(TargetNotPublicException):
        validate_and_canonicalize_url("http://169.254.169.254/latest/meta-data")

    with pytest.raises(TargetNotPublicException):
        validate_and_canonicalize_url("http://10.0.0.5/internal")


def test_validate_unsupported_ports_rejected() -> None:
    """Verify ports outside 80 and 443 are rejected."""
    with pytest.raises(TrustLensException) as exc_info:
        validate_and_canonicalize_url("https://example.com:8080")
    assert exc_info.value.code == "PORT_NOT_ALLOWED"


def test_detect_sensitive_url() -> None:
    """Verify detection of secret/token parameters in URL query strings."""
    assert detect_sensitive_url("https://example.com/login?token=eyJhbGciOiJIUzI1NiJ9") is True
    assert detect_sensitive_url("https://example.com/api?api_key=secret12345") is True
    assert detect_sensitive_url("https://example.com/search?q=cybersecurity") is False


def test_redirect_tracker_loop_detection() -> None:
    """Verify redirect tracker detects redirect loops."""
    seen = ["https://example.com/page1", "https://example.com/page2"]
    with pytest.raises(TrustLensException) as exc_info:
        redirect_tracker.validate_next_hop(
            current_url="https://example.com/page2",
            location_header="https://example.com/page1",
            seen_urls=seen,
            allow_private_for_tests=True,
        )
    assert exc_info.value.code == "REDIRECT_LOOP_DETECTED"


def test_redirect_tracker_rejects_ssrf_destination() -> None:
    """Verify redirect to private IP is blocked."""
    seen = ["https://example.com/page1"]
    with pytest.raises(TargetNotPublicException):
        redirect_tracker.validate_next_hop(
            current_url="https://example.com/page1",
            location_header="http://127.0.0.1:80/admin",
            seen_urls=seen,
            allow_private_for_tests=False,
        )


def test_security_header_scanner_missing_headers() -> None:
    """Verify scanner flags missing HSTS, CSP, and X-Content-Type-Options."""
    headers = {"Server": "nginx"}
    result = security_header_scanner.analyze(headers=headers, is_https=True)

    assert "strict-transport-security" in result.headers
    assert result.headers["strict-transport-security"].finding_code == "HSTS_MISSING"

    assert "content-security-policy" in result.headers
    assert result.headers["content-security-policy"].finding_code == "CSP_MISSING"

    assert "x-content-type-options" in result.headers
    assert result.headers["x-content-type-options"].finding_code == "X_CONTENT_TYPE_OPTIONS_MISSING"
    assert result.points_total > 0


def test_security_header_scanner_adequate_headers() -> None:
    """Verify scanner recognizes configured security headers."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    result = security_header_scanner.analyze(headers=headers, is_https=True)
    assert result.headers["strict-transport-security"].is_adequate is True
    assert result.headers["content-security-policy"].is_adequate is True
    assert result.headers["x-content-type-options"].is_adequate is True
    assert result.points_total == 0
