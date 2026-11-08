"""RFC 9525 Service Identity Verification for TLS.

Implements strict RFC 9525 (superseding RFC 6125) identity matching for TLS:
- dNSName SAN verification for domain names.
- iPAddress SAN verification for IPv4/IPv6 addresses.
- Prohibits Common Name (CN) fallback.
- Restricts wildcard matching strictly to the complete left-most label.
- Prohibits partial wildcards (e.g., 'foo*') and wildcards matching IP addresses.
- Handles IDNA / Punycode (A-labels) and trailing dot normalization.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple
import idna


class RFC9525IdentityVerifier:
    """Verifies service identity in TLS certificates complying with RFC 9525."""

    @classmethod
    def verify(
        cls,
        reference_identity: str,
        dns_sans: List[str],
        ip_sans: List[str],
    ) -> Tuple[bool, str, Optional[str]]:
        """Verifies reference identity against presented SANs.

        Returns:
            (is_matched, match_status, matched_pattern)
            match_status is one of:
            - "MATCH_EXACT_DNS"
            - "MATCH_WILDCARD_DNS"
            - "MATCH_IP"
            - "MISMATCH_NO_SAN"
            - "MISMATCH_DNS"
            - "MISMATCH_IP"
            - "INVALID_REFERENCE_IDENTITY"
        """
        if not reference_identity or not isinstance(reference_identity, str):
            return False, "INVALID_REFERENCE_IDENTITY", None

        ref_clean = reference_identity.strip()

        # 1. Determine if reference identity is an IP address
        try:
            ref_ip = ipaddress.ip_address(ref_clean)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            return cls._verify_ip(ref_ip, ip_sans)
        else:
            return cls._verify_domain(ref_clean, dns_sans)

    @classmethod
    def _verify_ip(
        cls,
        ref_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        ip_sans: List[str],
    ) -> Tuple[bool, str, Optional[str]]:
        """Checks IP reference identity strictly against iPAddress SAN entries."""
        if not ip_sans:
            return False, "MISMATCH_NO_SAN", None

        for san in ip_sans:
            san_clean = san.strip()
            try:
                san_ip = ipaddress.ip_address(san_clean)
                if ref_ip == san_ip:
                    return True, "MATCH_IP", str(san_ip)
            except ValueError:
                continue

        return False, "MISMATCH_IP", None

    @classmethod
    def _verify_domain(
        cls,
        ref_domain: str,
        dns_sans: List[str],
    ) -> Tuple[bool, str, Optional[str]]:
        """Checks domain reference identity strictly against dNSName SAN entries (RFC 9525)."""
        if not dns_sans:
            return False, "MISMATCH_NO_SAN", None

        # Canonicalize reference domain: strip trailing dot, lowercase, convert to A-label
        norm_ref = cls._canonicalize_domain_name(ref_domain)
        if not norm_ref:
            return False, "INVALID_REFERENCE_IDENTITY", None

        ref_labels = norm_ref.split(".")

        for san in dns_sans:
            norm_san = cls._canonicalize_domain_name(san)
            if not norm_san:
                continue

            # Check exact match
            if norm_ref == norm_san:
                return True, "MATCH_EXACT_DNS", san

            # Check wildcard match (RFC 9525 Section 6.4.3)
            # Wildcard is ONLY valid if '*' is the complete left-most label
            if norm_san.startswith("*."):
                san_labels = norm_san.split(".")
                # Ensure wildcard character '*' only appears once and is the complete first label
                if san_labels[0] == "*" and "*" not in ".".join(san_labels[1:]):
                    # Wildcard cannot match an apex (must have exactly one more label in ref)
                    if len(ref_labels) == len(san_labels):
                        # Right-hand labels must match exactly
                        if ref_labels[1:] == san_labels[1:]:
                            # Wildcard matches any valid non-empty single label
                            if ref_labels[0]:
                                return True, "MATCH_WILDCARD_DNS", san

        return False, "MISMATCH_DNS", None

    @staticmethod
    def _canonicalize_domain_name(domain: str) -> Optional[str]:
        """Normalizes domain by removing trailing dot, converting to lowercase, and encoding to ASCII A-label."""
        d = domain.strip().rstrip(".").lower()
        if not d:
            return None

        # Check for wildcard prefix
        is_wildcard = d.startswith("*.")
        to_encode = d[2:] if is_wildcard else d

        try:
            ascii_encoded = idna.encode(to_encode).decode("ascii")
            return f"*.{ascii_encoded}" if is_wildcard else ascii_encoded
        except Exception:
            # Fallback to sanitized ASCII if not standard IDNA
            return f"*.{to_encode}" if is_wildcard else to_encode

