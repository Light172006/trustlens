"""Canonicalization and normalization of X.509 certificate attributes."""

from __future__ import annotations

import idna
from typing import Any, Dict, List, Tuple


class Canonicalizer:
    """Normalizes certificate records for uniform analysis and deduplication."""

    @staticmethod
    def normalize_domain(domain: str) -> Tuple[str, str]:
        """Normalizes domain string. Returns (ascii_canonical, unicode_canonical)."""
        domain_clean = domain.strip().lower().rstrip(".")
        if domain_clean.startswith("*."):
            prefix = "*."
            raw_host = domain_clean[2:]
        else:
            prefix = ""
            raw_host = domain_clean

        try:
            ascii_canonical = prefix + idna.encode(raw_host).decode("ascii")
            unicode_canonical = prefix + idna.decode(raw_host)
        except Exception:
            ascii_canonical = domain_clean
            unicode_canonical = domain_clean

        return ascii_canonical, unicode_canonical

    @classmethod
    def normalize_record(cls, record: Dict[str, Any]) -> Dict[str, Any]:
        """Performs idempotent in-place and returning normalization on a certificate record."""
        # Normalize SAN domains
        norm_sans: List[str] = []
        norm_dns: List[str] = []
        norm_wildcards: List[str] = []

        if "domain_identity" in record:
            domain_id = record["domain_identity"]
            for san in domain_id.get("dns_san_entries", []):
                ascii_dom, unicode_dom = cls.normalize_domain(san)
                norm_dns.append(ascii_dom)
                norm_sans.append(ascii_dom)
                if ascii_dom.startswith("*.") or "*" in ascii_dom:
                    norm_wildcards.append(ascii_dom)

            for ip in domain_id.get("ip_san_entries", []):
                ip_clean = ip.strip()
                norm_sans.append(ip_clean)

            domain_id["dns_san_entries"] = sorted(list(set(norm_dns)))
            domain_id["subject_alternative_names"] = sorted(list(set(norm_sans)))
            domain_id["wildcard_san_indicators"] = sorted(list(set(norm_wildcards)))
            domain_id["has_wildcard"] = len(domain_id["wildcard_san_indicators"]) > 0
            domain_id["san_count"] = len(domain_id["subject_alternative_names"])

        # Normalize fingerprints to lowercase hex
        if "sha256_fingerprint" in record:
            record["sha256_fingerprint"] = record["sha256_fingerprint"].lower().strip()
        if "sha1_fingerprint" in record:
            record["sha1_fingerprint"] = record["sha1_fingerprint"].lower().strip()
        if "spki_sha256_fingerprint" in record:
            record["spki_sha256_fingerprint"] = record["spki_sha256_fingerprint"].lower().strip()

        return record

