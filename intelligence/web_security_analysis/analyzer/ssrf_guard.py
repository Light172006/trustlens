"""
TrustLens Web Security Analyzer - Server-Side Request Forgery (SSRF) Guard
Provides multi-layered network defense against internal, private, loopback, and cloud metadata targets.
"""

import ipaddress
import logging
import re
import socket
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse

logger = logging.getLogger("ssrf_guard")

# Prohibited internal/reserved domains
BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "broadcasthost",
    "metadata.google.internal", "instance-data",
}

BLOCKED_DOMAIN_SUFFIXES = (
    ".local", ".internal", ".corp", ".lan", ".home", ".home.arpa",
    ".test", ".example", ".invalid", ".localhost",
)

# Known Cloud Metadata IP targets
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS, GCP, Azure, OpenStack
    ipaddress.ip_address("169.254.169.253"),  # DNS link-local
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
}


class SSRFSecurityException(Exception):
    """Raised when an SSRF violation or attempt to access restricted network resources is detected."""
    pass


def is_ip_address(hostname: str) -> bool:
    """Detects whether a hostname string represents an IPv4 or IPv6 address in standard or alternative notation."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Detect integer decimal, hex, or octal IP encodings (e.g., 2130706433 or 0x7f000001)
    if re.match(r"^(\d+|0x[0-9a-fA-F]+)$", hostname):
        try:
            val = int(hostname, 0)
            if 0 <= val <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    return False


def parse_ip_literal(hostname: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Parses standard or integer/hex-encoded IP address literals."""
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass

    if re.match(r"^(\d+|0x[0-9a-fA-F]+)$", hostname):
        try:
            val = int(hostname, 0)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    return None


def is_restricted_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address belongs to restricted, private, loopback, link-local,
    or cloud metadata address ranges.
    """
    # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip in CLOUD_METADATA_IPS:
        return True, f"Cloud metadata endpoint blocked ({ip})"

    if ip.is_loopback:
        return True, f"Loopback address blocked ({ip})"

    if ip.is_private:
        return True, f"Private RFC 1918 / RFC 4193 network address blocked ({ip})"

    if ip.is_link_local:
        return True, f"Link-local address blocked ({ip})"

    if ip.is_multicast:
        return True, f"Multicast address blocked ({ip})"

    if ip.is_reserved:
        return True, f"Reserved IETF address blocked ({ip})"

    if ip.is_unspecified:
        return True, f"Unspecified 0.0.0.0 / :: address blocked ({ip})"

    # Carrier-grade NAT (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat_net = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat_net:
            return True, f"Carrier-Grade NAT address blocked ({ip})"

    return False, ""


def validate_hostname_ssrf(hostname: str) -> None:
    """Validates hostname against prohibited internal names and suffixes."""
    clean_host = hostname.strip().lower()
    if not clean_host:
        raise SSRFSecurityException("Empty hostname.")

    if clean_host in BLOCKED_HOSTNAMES:
        raise SSRFSecurityException(f"Restricted internal hostname blocked: '{clean_host}'")

    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if clean_host.endswith(suffix):
            raise SSRFSecurityException(f"Restricted internal domain suffix blocked: '{clean_host}'")

    # If hostname is an IP literal, validate immediately
    ip_obj = parse_ip_literal(clean_host)
    if ip_obj is not None:
        blocked, reason = is_restricted_ip(ip_obj)
        if blocked:
            raise SSRFSecurityException(f"SSRF Policy Violation: {reason}")


def resolve_and_validate_destination(hostname: str, port: int = 443) -> List[str]:
    """
    Performs DNS resolution and validates that ALL resolved IP addresses are safe public IPs.
    Prevents DNS rebinding and mixed public/private responses.
    """
    validate_hostname_ssrf(hostname)

    # Check if host is direct IP literal
    ip_obj = parse_ip_literal(hostname)
    if ip_obj is not None:
        blocked, reason = is_restricted_ip(ip_obj)
        if blocked:
            raise SSRFSecurityException(f"SSRF Policy Violation: {reason}")
        return [str(ip_obj)]

    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                blocked, reason = is_restricted_ip(ip)
                if blocked:
                    raise SSRFSecurityException(f"DNS resolved to restricted address ({reason}) for host '{hostname}'")
                if str(ip) not in resolved_ips:
                    resolved_ips.append(str(ip))
            except ValueError:
                raise SSRFSecurityException(f"Invalid resolved IP address: '{ip_str}'")
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failure for host '{hostname}': {e}")
        return []

    if not resolved_ips:
        raise SSRFSecurityException(f"Could not resolve host '{hostname}' to any valid IP address.")

    return resolved_ips
