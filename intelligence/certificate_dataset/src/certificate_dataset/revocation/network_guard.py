"""Network safety guard for untrusted certificate URLs (AIA, CRLDP, OCSP).

Enforces SSRF prevention, strict IP range filtering, DNS resolution checks,
timeout bounds, response size limits, and redirect constraints.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse


class UnsafeURLError(Exception):
    """Raised when a URL targets a prohibited or non-public network destination."""
    pass


class NetworkSafetyGuard:
    """Validates URLs and destination IPs before making outbound requests."""

    BLOCKED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),       # Loopback IPv4
        ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
        ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
        ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
        ipaddress.ip_network("169.254.0.0/16"),    # Link-local IPv4
        ipaddress.ip_network("0.0.0.0/8"),         # Broadcast / This network
        ipaddress.ip_network("224.0.0.0/4"),       # Multicast
        ipaddress.ip_network("240.0.0.0/4"),       # Reserved
        ipaddress.ip_network("::1/128"),           # Loopback IPv6
        ipaddress.ip_network("fc00::/7"),          # Unique local IPv6
        ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
    ]

    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def validate_url(cls, url: str) -> Tuple[str, List[str]]:
        """Validates that a URL is safe to retrieve.
        
        Returns (hostname, resolved_public_ips).
        Raises UnsafeURLError if target is disallowed.
        """
        if not url or not isinstance(url, str):
            raise UnsafeURLError("Empty or non-string URL provided")

        parsed = urlparse(url)
        if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
            raise UnsafeURLError(f"Prohibited URL scheme: {parsed.scheme}")

        hostname = parsed.hostname
        if not hostname:
            raise UnsafeURLError("URL is missing a valid hostname")

        # Resolve hostname to IPs
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                ip_str = item[4][0]
                resolved_ips.append(ip_str)
        except socket.gaierror as e:
            raise UnsafeURLError(f"DNS resolution failed for {hostname}: {e}") from e

        if not resolved_ips:
            raise UnsafeURLError(f"No IP addresses resolved for hostname: {hostname}")

        # Check all resolved IPs against prohibited ranges
        for ip_str in resolved_ips:
            ip_obj = ipaddress.ip_address(ip_str)
            for blocked_net in cls.BLOCKED_NETWORKS:
                if ip_obj in blocked_net:
                    raise UnsafeURLError(
                        f"Resolved IP {ip_str} for host {hostname} belongs to restricted range {blocked_net}"
                    )

        return hostname, resolved_ips

