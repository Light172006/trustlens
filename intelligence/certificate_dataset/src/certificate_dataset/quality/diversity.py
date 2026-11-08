"""Data quality, diversity profiling, and anomaly analysis for certificate corpora."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List
import statistics


class DiversityProfiler:
    """Computes PKI diversity metrics, concentration indices, and quality indicators."""

    @classmethod
    def profile(cls, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Profiles a list of certificate records."""
        total_records = len(records)
        if total_records == 0:
            return {"total_records": 0, "status": "EMPTY"}

        fingerprints = [r["sha256_fingerprint"] for r in records if "sha256_fingerprint" in r]
        unique_fps = set(fingerprints)
        duplicate_fps_count = total_records - len(unique_fps)

        # Public keys (SPKI)
        spki_fps = [
            r.get("spki_sha256_fingerprint") or r.get("public_key", {}).get("spki_sha256_fingerprint")
            for r in records
        ]
        spki_fps_valid = [s for s in spki_fps if s]
        unique_spki_count = len(set(spki_fps_valid))
        reused_keys_count = len(spki_fps_valid) - unique_spki_count

        # Issuers
        issuers = [r.get("issuer_dn") or r.get("issuer", {}).get("issuer_dn") for r in records]
        issuers_valid = [i for i in issuers if i]
        issuer_counts = Counter(issuers_valid)
        unique_issuers_count = len(issuer_counts)

        # Calculate Herfindahl-Hirschman Index (HHI) for issuer concentration
        # HHI ranges from 0 to 10,000 (10,000 = monopoly / single issuer)
        hhi = 0.0
        if len(issuers_valid) > 0:
            for count in issuer_counts.values():
                share_pct = (count / len(issuers_valid)) * 100.0
                hhi += share_pct ** 2

        # Certificate Types
        cert_types = Counter([r.get("certificate_type", "UNKNOWN") for r in records])

        # Algorithms and key sizes
        key_algos = Counter([
            r.get("public_key_algorithm") or r.get("public_key", {}).get("algorithm", "UNKNOWN")
            for r in records
        ])
        sig_algos = Counter([
            r.get("signature_algorithm") or r.get("signature", {}).get("algorithm", "UNKNOWN")
            for r in records
        ])
        key_sizes = Counter([
            str(r.get("key_size_bits") or r.get("public_key", {}).get("key_size_bits", "0"))
            for r in records
        ])

        # Validity durations
        durations = [
            r.get("validity_duration_days") or r.get("validity", {}).get("validity_duration_days", 0.0)
            for r in records
        ]
        durations_valid = [d for d in durations if d > 0]
        min_days = round(min(durations_valid), 2) if durations_valid else 0.0
        max_days = round(max(durations_valid), 2) if durations_valid else 0.0
        mean_days = round(statistics.mean(durations_valid), 2) if durations_valid else 0.0
        median_days = round(statistics.median(durations_valid), 2) if durations_valid else 0.0

        # Quality and anomalies
        anomalies: List[Dict[str, Any]] = []
        for r in records:
            fp = r.get("sha256_fingerprint", "unknown")
            san_count = r.get("domain_identity", {}).get("san_count", 0)
            if r.get("certificate_type") == "LEAF" and san_count == 0:
                anomalies.append({"fingerprint": fp, "type": "MISSING_SAN_IN_LEAF"})
            if r.get("public_key", {}).get("security_classification") in ("INSECURE", "DEPRECATED"):
                anomalies.append({"fingerprint": fp, "type": "WEAK_PUBLIC_KEY"})
            if r.get("signature", {}).get("security_classification") in ("INSECURE", "DEPRECATED"):
                anomalies.append({"fingerprint": fp, "type": "WEAK_SIGNATURE"})

        return {
            "total_records": total_records,
            "unique_certificates": len(unique_fps),
            "duplicate_fingerprints_count": duplicate_fps_count,
            "unique_public_keys": unique_spki_count,
            "reused_keys_count": reused_keys_count,
            "unique_issuers": unique_issuers_count,
            "issuer_hhi_concentration": round(hhi, 2),
            "certificate_type_distribution": dict(cert_types),
            "public_key_algorithm_distribution": dict(key_algos),
            "signature_algorithm_distribution": dict(sig_algos),
            "key_size_distribution": dict(key_sizes),
            "validity_duration_statistics": {
                "min_days": min_days,
                "max_days": max_days,
                "mean_days": mean_days,
                "median_days": median_days,
            },
            "anomalies_detected_count": len(anomalies),
            "anomalies_sample": anomalies[:20],
        }

