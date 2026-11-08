"""
TrustLens Web Security Analyzer - URL & Target Domain Validator
Validates, normalizes, sanitizes input URLs, and enforces strict scheme and port policies.
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import idna
from tld import get_fld

from ssrf_guard import SSRFSecurityException, parse_ip_literal, validate_hostname_ssrf

logger = logging.getLogger("url_validator")

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}


class URLValidationError(ValueError):
    """Raised when an input URL fails syntax, scheme, or safety validation."""
    pass


def normalize_target_url(raw_url: str) -> Dict[str, Any]:
    """
    Parses, validates, normalizes, and sanitizes input URL.
    Returns normalized metadata dictionary.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise URLValidationError("Target URL must be a non-empty string.")

    cleaned_url = raw_url.strip()

    # Prepend https:// if no scheme provided
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned_url):
        cleaned_url = "https://" + cleaned_url

    try:
        parsed = urlparse(cleaned_url)
    except Exception as e:
        raise URLValidationError(f"Malformed URL string: {e}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    if not parsed.netloc:
        raise URLValidationError("URL lacks a valid network location / host.")

    # Reject credentials in URL (user:pass@host)
    if parsed.username or parsed.password:
        raise URLValidationError("Credentials in URL (user:password@host) are prohibited.")

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("Invalid hostname.")

    hostname = hostname.strip().lower()

    # Port validation
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    if port not in ALLOWED_PORTS:
        raise URLValidationError(f"Port {port} is not in permitted web ports {ALLOWED_PORTS}.")

    # Check if host is IPv6 literal
    if ":" in hostname:
        try:
            ip_obj = parse_ip_literal(hostname)
            if ip_obj is not None:
                from ssrf_guard import is_restricted_ip
                blocked, reason = is_restricted_ip(ip_obj)
                if blocked:
                    raise URLValidationError(f"SSRF Security Violation: {reason}")
            ascii_hostname = f"[{hostname}]"
        except ValueError:
            raise URLValidationError(f"Invalid IPv6 hostname '{hostname}'")
    else:
        # IDN / Punycode normalization
        try:
            ascii_hostname = idna.encode(hostname).decode("ascii")
        except Exception as e:
            raise URLValidationError(f"IDN Punycode encoding failed for host '{hostname}': {e}")

    # SSRF verification on hostname
    try:
        validate_hostname_ssrf(ascii_hostname)
    except SSRFSecurityException as e:
        raise URLValidationError(f"SSRF Security Violation: {e}")

    # Registrable domain extraction via Public Suffix List
    fld = get_fld(ascii_hostname, fix_protocol=True, fail_silently=True)
    if not fld:
        parts = ascii_hostname.split(".")
        if len(parts) >= 2:
            fld = ".".join(parts[-2:])
        else:
            fld = ascii_hostname

    # Reconstruct sanitized URL without fragments or query tokens
    sanitized_netloc = ascii_hostname if (port == 80 and scheme == "http") or (port == 443 and scheme == "https") else f"{ascii_hostname}:{port}"
    clean_path = parsed.path if parsed.path else "/"
    normalized_url = urlunparse((scheme, sanitized_netloc, clean_path, "", "", ""))

    return {
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": ascii_hostname,
        "registrable_domain": fld.lower(),
        "port": port,
        "is_idn": ascii_hostname.startswith("xn--") or (ascii_hostname != hostname),
        "path": clean_path,
    }
