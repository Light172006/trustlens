"""TrustLens Intelligence — Web Security and TLS Feature Extraction."""

from typing import Any
from urllib.parse import urlparse

from trustlens_intelligence.schemas.evidence import HttpEvidence, TlsCertificateEvidence

LEGACY_TLS_PROTOCOLS = frozenset(["tlsv1.0", "tlsv1.1", "tlsv1", "sslv3", "sslv2"])


def extract_security_features(
    scheme: str | None,
    http: HttpEvidence | None,
    tls: TlsCertificateEvidence | None,
) -> dict[str, Any]:
    """Extract web security and TLS configuration features.

    Carefully preserves None for unobserved checks instead of assuming success.
    """
    is_https = (scheme or "").lower() == "https"

    # HTTP layer extraction
    redirect_count = 0
    cross_domain_redirect = False
    http_to_https = False
    has_hsts = False
    has_csp = False
    has_x_cto = False
    has_referrer = False
    has_permissions = False
    insecure_cookies = 0
    missing_httponly = 0
    missing_samesite = 0

    if http:
        redirect_count = http.redirect_count
        headers = http.security_headers or {}

        # Inspect headers
        has_hsts = bool(headers.get("strict-transport-security"))
        has_csp = bool(headers.get("content-security-policy"))
        x_cto_val = headers.get("x-content-type-options")
        has_x_cto = bool(x_cto_val and "nosniff" in x_cto_val.lower())
        has_referrer = bool(headers.get("referrer-policy"))
        has_permissions = bool(headers.get("permissions-policy"))

        # Inspect redirects
        if http.redirects:
            first_hop = http.redirects[0]
            last_hop = http.redirects[-1]
            try:
                first_parsed = urlparse(first_hop.source_url)
                last_parsed = urlparse(last_hop.destination_url)
                if first_parsed.scheme == "http" and last_parsed.scheme == "https":
                    http_to_https = True
                first_host = first_parsed.netloc.split(":")[0].lower()
                last_host = last_parsed.netloc.split(":")[0].lower()
                if first_host and last_host and first_host != last_host:
                    cross_domain_redirect = True
            except Exception:
                pass

        # Inspect cookies
        for cookie in http.cookies:
            if not cookie.secure:
                insecure_cookies += 1
            if not cookie.httponly:
                missing_httponly += 1
            if not cookie.samesite or cookie.samesite.lower() == "none":
                # 'none' without secure is insecure, but any missing samesite attribute is tracked
                if not cookie.samesite:
                    missing_samesite += 1

    # TLS layer extraction
    tls_valid: bool | None = None
    cert_chain_valid: bool | None = None
    cert_hostname_match: bool | None = None
    cert_is_expired: bool | None = None
    cert_days_until_expiry: int | None = None
    is_legacy_tls: bool | None = None

    if tls:
        tls_valid = tls.valid
        cert_chain_valid = tls.chain_valid
        cert_hostname_match = tls.hostname_match
        cert_is_expired = tls.is_expired
        cert_days_until_expiry = tls.days_until_expiry

        if tls.protocol_version:
            proto_clean = tls.protocol_version.strip().lower()
            is_legacy_tls = proto_clean in LEGACY_TLS_PROTOCOLS
        else:
            is_legacy_tls = None

    return {
        "is_https": is_https,
        "redirect_count": redirect_count,
        "has_cross_domain_redirect": cross_domain_redirect,
        "http_to_https_redirect": http_to_https,
        "has_hsts": has_hsts,
        "has_csp": has_csp,
        "has_x_content_type_options": has_x_cto,
        "has_referrer_policy": has_referrer,
        "has_permissions_policy": has_permissions,
        "insecure_cookie_count": insecure_cookies,
        "missing_httponly_cookie_count": missing_httponly,
        "missing_samesite_cookie_count": missing_samesite,
        "tls_valid": tls_valid,
        "cert_chain_valid": cert_chain_valid,
        "cert_hostname_match": cert_hostname_match,
        "cert_is_expired": cert_is_expired,
        "cert_days_until_expiry": cert_days_until_expiry,
        "is_legacy_tls": is_legacy_tls,
    }

