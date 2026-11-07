"""URL validation, normalization, and comprehensive Server-Side Request Forgery (SSRF) defense."""

import ipaddress
import re
from urllib.parse import parse_qsl, urlparse, urlunparse

import dns.resolver
import idna

from app.config import settings
from app.core.exceptions import (
    TargetNotPublicException,
    TrustLensException,
)
from app.core.logging import logger

# Banned cloud metadata and internal infrastructure hostnames
DISALLOWED_HOSTNAMES: set[str] = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "metadata.internal",
    "vault.internal",
    "consul.internal",
    "docker.for.win.localhost",
    "host.docker.internal",
}

# Regex to detect embedded secret / token parameters in URLs
SENSITIVE_PARAM_PATTERN = re.compile(
    r"(?i)(token|key|secret|password|auth|api_key|session|access_token|jwt|signature|sig)"
)


class ValidatedTarget:
    """Encapsulates validated, canonicalized target URL and pinned public IP addresses."""

    def __init__(
        self,
        original_url: str,
        canonical_url: str,
        scheme: str,
        host: str,
        port: int,
        resolved_ips: list[str],
        is_sensitive: bool = False,
    ) -> None:
        self.original_url = original_url
        self.canonical_url = canonical_url
        self.scheme = scheme
        self.host = host
        self.port = port
        self.resolved_ips = resolved_ips
        self.is_sensitive = is_sensitive

    def __repr__(self) -> str:
        return f"<ValidatedTarget host={self.host} port={self.port} ips={self.resolved_ips}>"


def is_ip_globally_routable(ip_str: str) -> bool:
    """Validate that an IPv4 or IPv6 address is strictly public and globally routable.

    Explicitly blocks:
    - Loopback (127.0.0.0/8, ::1)
    - Private / RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Cloud Metadata (169.254.169.254)
    - Carrier-grade NAT (100.64.0.0/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - IPv4-mapped IPv6 (::ffff:0:0/96)
    - Reserved, Unspecified, and Documentation ranges
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Check for IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_globally_routable(str(ip.ipv4_mapped))

    if ip.is_loopback:
        return False
    if ip.is_private:
        return False
    if ip.is_link_local:
        return False
    if ip.is_multicast:
        return False
    if ip.is_unspecified:
        return False
    if ip.is_reserved:
        return False

    # Block 169.254.0.0/16 explicitly
    if isinstance(ip, ipaddress.IPv4Address):
        link_local_net = ipaddress.ip_network("169.254.0.0/16")
        cgnat_net = ipaddress.ip_network("100.64.0.0/10")
        if ip in link_local_net or ip in cgnat_net:
            return False

    # Global routability check
    return ip.is_global


def resolve_hostname_ips(hostname: str) -> list[str]:
    """Resolve A and AAAA DNS records for target hostname."""
    resolved_ips: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 2.5

    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, record_type)
            for rdata in answers:
                resolved_ips.append(str(rdata))
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            pass
        except Exception as exc:
            logger.debug(f"DNS resolution exception for {hostname} ({record_type}): {exc}")

    return resolved_ips


def detect_sensitive_url(url_string: str) -> bool:
    """Analyze query parameters for presence of sensitive authentication or session tokens."""
    try:
        parsed = urlparse(url_string)
        if not parsed.query:
            return False
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for key, value in params:
            if SENSITIVE_PARAM_PATTERN.search(key):
                return True
            # Long random alphanumeric token in query param
            if len(value) >= 32 and re.match(r"^[A-Za-z0-9_\-\.~]+$", value):
                return True
        return False
    except Exception:
        return False


def validate_and_canonicalize_url(
    raw_url: str,
    treat_as_sensitive: bool = False,
    allow_private_for_tests: bool = False,
) -> ValidatedTarget:
    """Strictly validate, canonicalize, and verify public IP routing for a submitted URL.

    Raises:
        TargetNotPublicException: If URL resolves to non-public / prohibited IP.
        SSRFSecurityViolation: If malicious redirect / forbidden host is detected.
        TrustLensException: If URL is malformed or uses unsupported protocols.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise TrustLensException(
            message="A valid URL string is required.",
            code="VALIDATION_ERROR",
            status_code=400,
        )

    cleaned = raw_url.strip()
    if len(cleaned) > 2048:
        raise TrustLensException(
            message="URL exceeds maximum length of 2048 characters.",
            code="URL_TOO_LONG",
            status_code=400,
        )

    # Parse URL
    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        raise TrustLensException(
            message=f"Malformed URL: {exc}",
            code="MALFORMED_URL",
            status_code=400,
        )

    # 1. Scheme Validation (HTTP and HTTPS only)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise TrustLensException(
            message=f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.",
            code="UNSUPPORTED_URL_SCHEME",
            status_code=400,
        )

    # 2. Reject embedded user credentials (e.g. http://user:pass@host)
    if parsed.username or parsed.password:
        raise TrustLensException(
            message="URLs containing embedded user credentials (username/password) are rejected.",
            code="CREDENTIALS_IN_URL_REJECTED",
            status_code=400,
        )

    # 3. Hostname normalization
    raw_host = parsed.hostname
    if not raw_host:
        raise TrustLensException(
            message="The URL must contain a valid hostname.",
            code="MISSING_HOSTNAME",
            status_code=400,
        )

    # Normalize IDNA (Punycode) safely
    try:
        ascii_host = idna.encode(raw_host.lower().strip(".")).decode("ascii")
    except Exception:
        raise TrustLensException(
            message="Invalid or malformed internationalized domain name (IDNA).",
            code="INVALID_HOSTNAME_ENCODING",
            status_code=400,
        )

    # Reject known internal hostnames
    if ascii_host in DISALLOWED_HOSTNAMES:
        raise TargetNotPublicException()

    # 4. Port restrictions (strictly 80 and 443)
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    elif port not in settings.SCAN_ALLOWED_PORTS:
        raise TrustLensException(
            message=f"Port {port} is not supported. TrustLens only inspects standard web ports (80, 443).",
            code="PORT_NOT_ALLOWED",
            status_code=400,
        )

    # 5. DNS Resolution and IP Validation (SSRF Defense)
    # Check if host is direct IP literal
    try:
        ipaddress.ip_address(ascii_host)
        resolved_ips = [ascii_host]
    except ValueError:
        resolved_ips = resolve_hostname_ips(ascii_host)

    if not resolved_ips:
        raise TrustLensException(
            message=f"Failed to resolve DNS records for hostname '{ascii_host}'.",
            code="DNS_RESOLUTION_FAILED",
            status_code=400,
        )

    # Validate that EVERY resolved IP address is globally routable
    if not allow_private_for_tests:
        for ip in resolved_ips:
            if not is_ip_globally_routable(ip):
                logger.warning(
                    f"SSRF defense triggered: Host '{ascii_host}' resolved to non-public IP '{ip}'"
                )
                raise TargetNotPublicException()

    # 6. Canonicalize URL (strip fragment, normalize default port, preserve query)
    netloc = ascii_host
    if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
        netloc = f"{ascii_host}:{port}"

    path = parsed.path or "/"
    canonical_url = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    # 7. Sensitive URL detection
    is_sensitive = treat_as_sensitive or detect_sensitive_url(canonical_url)

    return ValidatedTarget(
        original_url=cleaned,
        canonical_url=canonical_url,
        scheme=scheme,
        host=ascii_host,
        port=port,
        resolved_ips=resolved_ips,
        is_sensitive=is_sensitive,
    )
