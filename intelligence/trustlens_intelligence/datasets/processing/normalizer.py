"""TrustLens Intelligence — URL Normalization and Canonicalization.

Performs strict RFC 3986 URL normalization, IDNA/Punycode encoding,
standard port stripping, userinfo isolation, and registrable domain extraction.
"""

from dataclasses import dataclass
import hashlib
import posixpath
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

import idna

# Common public suffixes for heuristic registrable domain extraction
COMMON_MULTI_TLDS = {
    "co.uk",
    "gov.uk",
    "ac.uk",
    "org.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.nz",
    "co.jp",
    "com.br",
    "co.in",
    "net.in",
    "org.in",
    "gen.in",
    "firm.in",
    "ind.in",
    "ac.in",
    "edu.in",
    "res.in",
    "gov.in",
    "mil.in",
}


@dataclass(frozen=True)
class NormalizedURL:
    """Canonical representation of a normalized URL."""

    original_url: str
    canonical_url: str
    scheme: str
    host: str
    registrable_domain: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    userinfo: str | None
    canonical_hash: str


def extract_registrable_domain(host: str) -> str:
    """Extract registrable domain (e.g. sub.example.co.uk -> example.co.uk)."""
    cleaned = host.lower().strip(".")
    # If IP address, return host as-is
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", cleaned) or ":" in cleaned:
        return cleaned

    parts = cleaned.split(".")
    if len(parts) <= 2:
        return cleaned

    # Check for two-part TLDs (e.g., co.uk, com.au)
    two_tld = f"{parts[-2]}.{parts[-1]}"
    if two_tld in COMMON_MULTI_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{two_tld}"

    return f"{parts[-2]}.{parts[-1]}"


class URLNormalizer:
    """Strict RFC 3986 URL canonicalization and hashing engine."""

    def normalize(self, raw_url: str) -> NormalizedURL:
        """Canonicalize raw URL according to strict normalization rules."""
        raw_stripped = raw_url.strip()
        lower_prefix = raw_stripped[:8].lower()
        if not (lower_prefix.startswith("http://") or lower_prefix.startswith("https://")):
            raw_stripped = f"http://{raw_stripped}"

        parsed = urlparse(raw_stripped)

        # 1. Scheme normalization (lowercase)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            scheme = "http"

        # 2. Userinfo isolation
        has_userinfo = bool(parsed.username or parsed.password)
        userinfo = None
        if has_userinfo:
            userinfo = f"{parsed.username or ''}:{parsed.password or ''}"

        # 3. Host normalization & Punycode encoding
        raw_host = (parsed.hostname or "").strip().lower()
        try:
            # Handle IDNA / Punycode
            encoded_host = idna.encode(raw_host).decode("ascii")
        except Exception:
            encoded_host = raw_host

        # 4. Port normalization (strip 80 for http, 443 for https)
        port = None
        try:
            port = parsed.port
        except ValueError:
            port = -1

        include_port = False
        if port is not None and port > 0:
            if scheme == "http" and port != 80:
                include_port = True
            elif scheme == "https" and port != 443:
                include_port = True

        netloc = f"{encoded_host}:{port}" if include_port else encoded_host

        # 5. Path normalization (collapse duplicate slashes, resolve . and ..)
        raw_path = parsed.path or "/"
        # Normalize slashes
        norm_path = posixpath.normpath(unquote(raw_path))
        if raw_path.endswith("/") and not norm_path.endswith("/"):
            norm_path += "/"
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path

        # Quote safe chars
        canonical_path = quote(norm_path, safe="/:@!$&'()*+,;=")

        # 6. Query normalization (sort keys for canonical deduplication)
        query = parsed.query
        canonical_query = ""
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            pairs.sort(key=lambda x: (x[0], x[1]))
            canonical_query = urlencode(pairs)

        # 7. Reassemble canonical URL (omit fragments per RFC 3986 for HTTP requests)
        canonical_url = urlunparse((scheme, netloc, canonical_path, "", canonical_query, ""))

        # 8. Extract registrable domain and canonical SHA-256 hash
        registrable_domain = extract_registrable_domain(encoded_host)
        canonical_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()

        return NormalizedURL(
            original_url=raw_url,
            canonical_url=canonical_url,
            scheme=scheme,
            host=encoded_host,
            registrable_domain=registrable_domain,
            port=port if include_port else None,
            path=canonical_path,
            query=canonical_query,
            has_userinfo=has_userinfo,
            userinfo=userinfo,
            canonical_hash=canonical_hash,
        )
