"""Deduplication and entity linking engine for certificate corpora."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple


class Deduplicator:
    """Detects and resolves certificate-level, key-level, and cross-source duplicates."""

    def __init__(self):
        self._seen_fingerprints: Set[str] = set()
        self._seen_spkis: Dict[str, List[str]] = {}
        self._precert_to_cert: Dict[str, str] = {}

    def process_record(self, record: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Processes a certificate record. Returns (is_duplicate, duplicate_metadata)."""
        fp = record["sha256_fingerprint"].lower().strip()
        spki = (
            record.get("spki_sha256_fingerprint")
            or record.get("public_key", {}).get("spki_sha256_fingerprint", "")
        ).lower().strip()

        is_dup_fp = fp in self._seen_fingerprints
        is_reused_key = (spki in self._seen_spkis) and not is_dup_fp

        if not is_dup_fp:
            self._seen_fingerprints.add(fp)

        if spki:
            if spki not in self._seen_spkis:
                self._seen_spkis[spki] = []
            if fp not in self._seen_spkis[spki]:
                self._seen_spkis[spki].append(fp)

        dup_meta = {
            "is_duplicate_fingerprint": is_dup_fp,
            "is_reused_public_key": is_reused_key,
            "key_sharing_count": len(self._seen_spkis.get(spki, [])),
        }

        return is_dup_fp, dup_meta

    def deduplicate_dataset(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filters out duplicate certificate fingerprints while maintaining first-seen provenance."""
        unique_records: List[Dict[str, Any]] = []
        seen = set()
        for r in records:
            fp = r["sha256_fingerprint"].lower().strip()
            if fp not in seen:
                seen.add(fp)
                unique_records.append(r)
        return unique_records

