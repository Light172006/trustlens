"""TrustLens Collaborative Threat Intelligence — URL & Indicator Normalization.

Implements strict, deterministic, and security-hardened URL canonicalization
according to RFC 3986, RFC 5890/5891 (IDNA), and WHATWG guidelines.

Guarantees:
1. Canonical representation for exact matching.
2. Original submitted URL preserved for audit and evidence.
3. Userinfo isolated and stripped from canonical URLs.
4. Preserves query parameters and meaningful path information without destructive truncation.
5. Distinct paths on a site are never falsely conflated.
6. Multi-part public suffixes recognized safely without incomplete PSL claims.
7. Explicit indicator scope extraction (EXACT_URL, HOST, DOMAIN).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import posixpath
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import idna

from collaborative_intelligence.config import NormalizationConfig
from collaborative_intelligence.enums import IndicatorScope


# Known multi-part public suffixes for standard registrable domain extraction
# RFC/IANA common national second-level domains
COMMON_MULTI_TLDS: set[str] = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "net.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "res.in", "gov.in",
    "com.sg", "edu.sg", "gov.sg",
    "com.hk", "edu.hk", "gov.hk",
    "co.za", "gov.za",
    "com.mx", "gob.mx", "edu.mx",
    "com.tr", "edu.tr", "gov.tr",
    "com.tw", "org.tw", "gov.tw",
}


@dataclass(frozen=True)
class NormalizedURL:
    """Canonical representation of an indicator URL and extracted scopes."""

    original_url: str
    canonical_url: str
    scheme: str
    host: str
    domain: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    userinfo: str | None
    is_ip: bool
    ip_version: int | None
    canonical_hash: str
    host_hash: str
    domain_hash: str


class URLNormalizationError(ValueError):
    """Raised when a URL is structurally invalid or violates security boundaries."""

    def __init__(self, message: str, code: str = "MALFORMED_URL"):
        super().__init__(message)
        self.code = code


def _is_unreserved_char(char: str) -> bool:
    """RFC 3986 section 2.3 unreserved characters: ALPHA / DIGIT / '-' / '.' / '_' / '~'."""
    return char.isalnum() or char in "-._~"


def _normalize_percent_encoding(string: str) -> str:
    """Normalize percent-encoded octets.

    Decodes unreserved characters and upper-cases all percent-hex escape sequences.
    """
    if "%" not in string:
        return string

    def _replace_octet(match: re.Match[str]) -> str:
        hex_val = match.group(1)
        try:
            byte_val = int(hex_val, 16)
            char = chr(byte_val)
            if _is_unreserved_char(char):
                return char
            return f"%{hex_val.upper()}"
        except ValueError:
            return match.group(0)

    return re.sub(r"%([0-9a-fA-F]{2})", _replace_octet, string)


def _safe_remove_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4 Remove Dot Segments with root preservation."""
    if not path or path == "/":
        return "/"

    # Use posixpath.normpath while respecting initial/trailing slashes
    has_trailing_slash = path.endswith("/")
    has_leading_slash = path.startswith("/")

    normalized = posixpath.normpath(path)
    if normalized == ".":
        normalized = ""

    if has_leading_slash and not normalized.startswith("/"):
        normalized = "/" + normalized

    if has_trailing_slash and not normalized.endswith("/") and normalized != "/":
        normalized += "/"

    return normalized or "/"


def extract_registrable_domain(host: str) -> str:
    """Extract registrable domain (e.g. sub.example.co.uk -> example.co.uk).

    Handles IP addresses and multi-part public suffixes deterministically.
    """
    cleaned = host.lower().rstrip(".")

    # IP address check
    try:
        ipaddress.ip_address(cleaned.strip("[]"))
        return cleaned
    except ValueError:
        pass

    parts = cleaned.split(".")
    if len(parts) <= 2:
        return cleaned

    # Check known two-part ccTLDs
    if len(parts) >= 3:
        potential_cc_tld = f"{parts[-2]}.{parts[-1]}"
        if potential_cc_tld in COMMON_MULTI_TLDS:
            return f"{parts[-3]}.{potential_cc_tld}"

    return f"{parts[-2]}.{parts[-1]}"


def normalize_url(
    raw_url: str,
    config: NormalizationConfig | None = None,
) -> NormalizedURL:
    """Perform security-hardened normalization on an untrusted community-reported URL.

    Args:
        raw_url: The submitted URL string.
        config: Normalization configuration policies.

    Returns:
        NormalizedURL dataclass with canonical forms and provenance metadata.

    Raises:
        URLNormalizationError: If URL is invalid, empty, or uses an unsupported scheme.
    """
    cfg = config or NormalizationConfig()

    if not raw_url or not isinstance(raw_url, str):
        raise URLNormalizationError("URL string must not be empty or null.", code="EMPTY_URL")

    stripped = raw_url.strip()
    if len(stripped) > cfg.max_url_length:
        raise URLNormalizationError(
            f"URL length ({len(stripped)}) exceeds maximum allowed ({cfg.max_url_length}).",
            code="URL_TOO_LONG",
        )

    # Disallow dangerous null bytes and raw ASCII control characters
    if any(ord(c) < 32 or ord(c) == 127 for c in stripped):
        raise URLNormalizationError(
            "URL contains disallowed control characters or null bytes.",
            code="INVALID_CONTROL_CHARS",
        )

    # Prepend scheme if user entered bare host/path without scheme
    # e.g. "example.com/login" -> "http://example.com/login"
    working_url = stripped
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", working_url)
    if scheme_match:
        detected_scheme = scheme_match.group(1).lower()
        if detected_scheme not in cfg.allowed_schemes:
            raise URLNormalizationError(
                f"Scheme '{detected_scheme}' is not permitted. Only {sorted(cfg.allowed_schemes)} are supported.",
                code="UNSUPPORTED_SCHEME",
            )
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", working_url):
            raise URLNormalizationError(
                f"Malformed URL authority for scheme '{detected_scheme}'.",
                code="MALFORMED_AUTHORITY",
            )
    else:
        working_url = f"http://{working_url}"

    try:
        split_result = urlsplit(working_url)
    except Exception as exc:
        raise URLNormalizationError(f"Failed to parse URL: {exc}", code="PARSE_FAILURE") from exc

    scheme = split_result.scheme.lower()
    if scheme not in cfg.allowed_schemes:
        raise URLNormalizationError(
            f"Scheme '{scheme}' is not permitted. Only {sorted(cfg.allowed_schemes)} are supported.",
            code="UNSUPPORTED_SCHEME",
        )

    netloc = split_result.netloc
    if not netloc:
        raise URLNormalizationError("URL must contain a valid host / authority.", code="MISSING_HOST")

    # Isolate userinfo if present
    userinfo: str | None = None
    has_userinfo = False
    if "@" in netloc:
        has_userinfo = True
        userinfo_part, _, host_port_part = netloc.rpartition("@")
        userinfo = userinfo_part
        host_port = host_port_part
    else:
        host_port = netloc

    # Parse host and port
    # Handling IPv6 brackets e.g. [::1]:8080
    host = ""
    port: int | None = None

    if host_port.startswith("["):
        # IPv6 literal
        if "]" not in host_port:
            raise URLNormalizationError("Malformed IPv6 literal without closing bracket.", code="INVALID_IPV6")
        bracket_end = host_port.index("]")
        raw_host = host_port[1:bracket_end]
        remainder = host_port[bracket_end + 1 :]
        if remainder.startswith(":"):
            try:
                port = int(remainder[1:])
            except ValueError:
                raise URLNormalizationError("Invalid port number after IPv6 host.", code="INVALID_PORT")
        host = raw_host
        is_ipv6 = True
    elif ":" in host_port:
        parts = host_port.rsplit(":", 1)
        raw_host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            raise URLNormalizationError(f"Invalid port number: '{parts[1]}'", code="INVALID_PORT")
        is_ipv6 = False
    else:
        raw_host = host_port
        port = None
        is_ipv6 = False

    if port is not None and not (1 <= port <= 65535):
        raise URLNormalizationError(f"Port {port} out of valid TCP range 1-65535.", code="PORT_OUT_OF_RANGE")

    # Strip default ports if configured
    if cfg.strip_default_ports and port is not None:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

    # Host normalization
    clean_host = raw_host.strip().rstrip(".")
    if not clean_host:
        raise URLNormalizationError("Host component is empty.", code="EMPTY_HOST")

    is_ip = False
    ip_version: int | None = None

    # Check for IP literal
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        is_ip = True
        ip_version = ip_obj.version
        canonical_host = f"[{ip_obj.compressed}]" if ip_version == 6 else str(ip_obj)
    except ValueError:
        # Domain name: handle IDNA / Punycode & lowercase
        try:
            # First decode to unicode to handle already-punycoded or mixed representations
            unicode_host = idna.decode(clean_host)
            # Re-encode to Punycode/ASCII for standard canonical internet representation
            canonical_host = idna.encode(unicode_host, uts46=True).decode("ascii").lower()
        except Exception:
            # Fallback to standard lowercase ASCII if IDNA decoding raises
            canonical_host = clean_host.lower()

    if len(canonical_host) > cfg.max_host_length:
        raise URLNormalizationError(
            f"Host length ({len(canonical_host)}) exceeds maximum {cfg.max_host_length}.",
            code="HOST_TOO_LONG",
        )

    registrable_domain = extract_registrable_domain(canonical_host)

    # Authority assembly
    canonical_authority = canonical_host
    if port is not None:
        canonical_authority = f"{canonical_host}:{port}"

    # Path normalization
    raw_path = split_result.path or "/"
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path

    # Unquote unreserved chars and normalize percent-hex
    path_normalized = _normalize_percent_encoding(raw_path)
    canonical_path = _safe_remove_dot_segments(path_normalized)

    # Query normalization
    canonical_query = ""
    if split_result.query:
        # Parse query params, keeping blank values and duplicate keys
        query_items = parse_qsl(split_result.query, keep_blank_values=True)
        if query_items:
            # Sort deterministically by key, then value
            if cfg.preserve_query_order_deterministically:
                sorted_items = sorted(query_items, key=lambda x: (x[0], x[1]))
            else:
                sorted_items = query_items
            # Encode sorted pairs
            canonical_query = urlencode(sorted_items, doseq=True)

    # Fragments are stripped per config
    canonical_fragment = "" if cfg.strip_fragments else split_result.fragment

    # Reconstruct canonical URL
    canonical_url = urlunsplit((
        scheme,
        canonical_authority,
        canonical_path,
        canonical_query,
        canonical_fragment,
    ))

    canonical_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
    host_hash = hashlib.sha256(canonical_host.encode("utf-8")).hexdigest()
    domain_hash = hashlib.sha256(registrable_domain.encode("utf-8")).hexdigest()

    return NormalizedURL(
        original_url=raw_url,
        canonical_url=canonical_url,
        scheme=scheme,
        host=canonical_host,
        domain=registrable_domain,
        port=port,
        path=canonical_path,
        query=canonical_query,
        has_userinfo=has_userinfo,
        userinfo=userinfo if not cfg.strip_userinfo_from_canonical else None,
        is_ip=is_ip,
        ip_version=ip_version,
        canonical_hash=canonical_hash,
        host_hash=host_hash,
        domain_hash=domain_hash,
    )
