"""TrustLens Intelligence — Structural URL and Host Feature Extraction.

Extracts domain hierarchy, IP-literal usage, IDNA punycode, and homoglyphs.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse
import idna

from trustlens_intelligence.common.url_utils import (
    extract_safe_hostname,
    has_userinfo_credentials,
    is_adversarial_or_standard_ip,
)


def is_ip_address(host: str) -> bool:
    """Detect whether host is any IPv4 (including octal, hex, dword, short), IPv6, or numeric representation."""
    return is_adversarial_or_standard_ip(host)


def count_subdomains(host: str) -> int:
    """Calculate the number of subdomain levels in a hostname."""
    if not host or is_ip_address(host):
        return 0

    clean_host = host.rstrip(".")
    parts = [p for p in clean_host.split(".") if p]
    if len(parts) <= 2:
        return 0

    # Common multi-part ccTLDs
    known_multi_cctlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "edu.au",
        "co.in", "gov.in", "org.in", "net.in",
        "co.jp", "com.br", "co.nz", "com.sg",
    }
    host_lower = clean_host.lower()
    for cctld in known_multi_cctlds:
        if host_lower.endswith(f".{cctld}"):
            return max(0, len(parts) - 3)

    return max(0, len(parts) - 2)


def has_homoglyphs_or_mixed_scripts(text: str) -> bool:
    """Check for suspicious non-ASCII or mixed-script characters often used in spoofing.

    Decodes IDNA Punycode (xn--) before inspection to detect homoglyphs hidden in Punycode.
    """
    if not text:
        return False

    inspect_text = text
    if "xn--" in text.lower():
        try:
            inspect_text = idna.decode(text.lower())
        except Exception:
            inspect_text = text

    has_latin = False
    has_confusable = False

    for char in inspect_text:
        cat = unicodedata.category(char)
        # Skip standard punctuation and digits
        if cat.startswith("P") or cat.startswith("N"):
            continue

        try:
            name = unicodedata.name(char)
            if "LATIN" in name:
                has_latin = True
            elif any(s in name for s in ("CYRILLIC", "GREEK", "HEBREW", "ARABIC")):
                has_confusable = True
        except ValueError:
            # Unknown unicode character
            has_confusable = True

    return (has_latin and has_confusable) or (not inspect_text.isascii() and has_confusable)


def extract_structural_features(url: str, explicit_host: str | None = None) -> dict[str, int | bool]:
    """Extract structural domain and host features.

    Args:
        url: Full URL string.
        explicit_host: Optional explicit hostname.

    Returns:
        Dictionary of structural metrics.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    host = explicit_host or extract_safe_hostname(explicit_host or url)

    port = None
    if parsed is not None:
        try:
            port = parsed.port
        except (ValueError, TypeError):
            # Out-of-range or non-numeric port explicitly indicates non-standard port anomaly
            port = -1

    is_ip = is_ip_address(host)
    subdomains = count_subdomains(host)
    is_puny = "xn--" in host.lower()
    has_confusables = has_homoglyphs_or_mixed_scripts(host)
    has_credentials = has_userinfo_credentials(url)

    # Non-standard port: port explicitly set and not standard 80 or 443
    has_non_standard = False
    if port is not None and port not in (80, 443):
        has_non_standard = True

    return {
        "subdomain_count": subdomains,
        "is_ip_host": is_ip,
        "is_punycode": is_puny,
        "has_homoglyphs": has_confusables,
        "has_non_standard_port": has_non_standard,
        "has_userinfo": has_credentials,
    }


