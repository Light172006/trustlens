"""TrustLens Intelligence — Common URL Canonicalization and Parsing Utilities.

Provides secure hostname parsing, default port stripping, userinfo stripping,
and IP address identification resilient against octal, hex, and dword evasion.
"""

import ipaddress
import re
from urllib.parse import urlparse, urlunparse
import idna


def extract_safe_hostname(url_or_host: str) -> str:
    """Safely extract and normalize hostname from a URL or raw host string.

    Correctly handles userinfo (e.g. user:pass@host) without confusing credentials
    with hostnames, strips default ports, removes IPv6 brackets, and strips trailing dots.
    """
    if not url_or_host or not url_or_host.strip():
        return ""

    text = url_or_host.strip()
    # Add dummy scheme if missing so urlparse treats domain as netloc rather than path
    if "://" not in text and not text.startswith("//"):
        text = "http://" + text

    try:
        parsed = urlparse(text)
        host = parsed.hostname
        if host:
            return host.lower().rstrip(".")
        # Fallback if urlparse fails to parse hostname
        netloc = parsed.netloc.split("@")[-1].split(":")[0]
        return netloc.strip("[]").lower().rstrip(".")
    except Exception:
        return ""


def has_userinfo_credentials(url: str) -> bool:
    """Check whether a URL contains userinfo credentials (e.g. user:pass@host)."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        return bool(parsed.username or parsed.password or ("@" in parsed.netloc))
    except Exception:
        return False


def is_adversarial_or_standard_ip(host: str) -> bool:
    """Identify whether a host string is any representation of an IP address.

    Detects:
    1. Standard IPv4 dotted-decimal (e.g. 192.168.1.1, 93.184.216.34)
    2. IPv6 standard & compressed (e.g. [::1], 2001:db8::1)
    3. Multi-part octal IPv4 (e.g. 0177.0.0.1, 0177.0000.0000.0001)
    4. Multi-part hex IPv4 (e.g. 0x7f.0.0.1, 127.0.0.0x1, 0x7f.0x0.0x0.0x1)
    5. Single dword decimal (e.g. 2130706433)
    6. Single dword hex (e.g. 0x7f000001)
    7. Shortened 2-part / 3-part IPv4 (e.g. 127.1, 127.0.1)
    """
    if not host:
        return False

    clean = host.strip("[]").strip().lower()

    # 1. Standard ipaddress parser
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        pass

    # 2. Dword integer representation (0 to 4294967295)
    if re.fullmatch(r"\d{1,10}", clean):
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    # 3. Dword hexadecimal representation (0x0 to 0xffffffff)
    if re.fullmatch(r"0x[0-9a-f]{1,8}", clean):
        return True

    # 4. Multi-part octal, hex, or shortened class-based IPv4
    parts = clean.split(".")
    if 2 <= len(parts) <= 4:
        valid_ip = True
        for part in parts:
            if re.fullmatch(r"0x[0-9a-f]+", part):
                continue
            if re.fullmatch(r"0[0-7]+", part):
                continue
            if re.fullmatch(r"\d+", part):
                if int(part) > 255 and len(parts) == 4:
                    valid_ip = False
                    break
            else:
                valid_ip = False
                break
        if valid_ip:
            return True

    return False


def canonicalize_url_strict(url: str) -> str:
    """Strict canonicalization for exact threat indicator matching.

    - Strips leading/trailing whitespace and fragments.
    - Normalizes scheme to lowercase.
    - Strips userinfo from canonical threat indicator identity.
    - Lowercases hostname and removes trailing FQDN dots.
    - Strips default ports (:80 for http, :443 for https).
    - Preserves path and query parameters exactly.
    """
    url = url.strip()
    if not url:
        return ""

    if "://" not in url and not url.startswith("//"):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        raw_host = (parsed.hostname or "").lower().rstrip(".")
        try:
            # Normalize internationalized domain name to ASCII punycode (PRD FR-03)
            host = idna.encode(raw_host).decode("ascii") if raw_host else ""
        except Exception:
            host = raw_host
        try:
            port = parsed.port
        except (ValueError, TypeError):
            port = None

        # Strip default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        path = parsed.path or "/"
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    except Exception:
        return url.strip()

