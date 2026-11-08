"""Dataset partitioning strategies with leak-free disjoint splits and overlap audits."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Set


class DatasetSplitter:
    """Creates reproducible, disjoint evaluation splits for ML and benchmarking."""

    @staticmethod
    def fingerprint_disjoint_split(
        records: List[Dict[str, Any]],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        seed: int = 42,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Splits strictly by unique certificate fingerprint."""
        rng = random.Random(seed)
        shuffled = list(records)
        rng.shuffle(shuffled)

        n = len(shuffled)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train = shuffled[:n_train]
        val = shuffled[n_train : n_train + n_val]
        test = shuffled[n_train + n_val :]

        return {"train": train, "val": val, "test": test}

    @staticmethod
    def public_key_disjoint_split(
        records: List[Dict[str, Any]],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        seed: int = 42,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Groups records by SPKI SHA-256 fingerprint, ensuring zero public-key leakage."""
        spki_groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            spki = (
                r.get("spki_sha256_fingerprint")
                or r.get("public_key", {}).get("spki_sha256_fingerprint", "unknown")
            )
            if spki not in spki_groups:
                spki_groups[spki] = []
            spki_groups[spki].append(r)

        unique_spkis = list(spki_groups.keys())
        rng = random.Random(seed)
        rng.shuffle(unique_spkis)

        n_keys = len(unique_spkis)
        n_train = int(n_keys * train_ratio)
        n_val = int(n_keys * val_ratio)

        train_keys = set(unique_spkis[:n_train])
        val_keys = set(unique_spkis[n_train : n_train + n_val])
        test_keys = set(unique_spkis[n_train + n_val :])

        train_records = [r for k in train_keys for r in spki_groups[k]]
        val_records = [r for k in val_keys for r in spki_groups[k]]
        test_records = [r for k in test_keys for r in spki_groups[k]]

        return {"train": train_records, "val": val_records, "test": test_records}

    @staticmethod
    def chronological_split(
        records: List[Dict[str, Any]],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Splits strictly forward in time by genuine not_before timestamp to prevent look-ahead bias."""
        def get_time(r: Dict[str, Any]) -> str:
            return r.get("not_before") or r.get("validity", {}).get("not_before", "1970-01-01T00:00:00Z")

        sorted_records = sorted(records, key=get_time)
        n = len(sorted_records)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train = sorted_records[:n_train]
        val = sorted_records[n_train : n_train + n_val]
        test = sorted_records[n_train + n_val :]

        return {"train": train, "val": val, "test": test}

    @staticmethod
    def audit_split_overlap(split_dict: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Verifies that no certificate fingerprints or public keys leak across partitions."""
        fps_by_split: Dict[str, Set[str]] = {}
        spkis_by_split: Dict[str, Set[str]] = {}

        for split_name, recs in split_dict.items():
            fps_by_split[split_name] = {r["sha256_fingerprint"] for r in recs if "sha256_fingerprint" in r}
            spkis_by_split[split_name] = {
                r.get("spki_sha256_fingerprint") or r.get("public_key", {}).get("spki_sha256_fingerprint")
                for r in recs
                if r.get("spki_sha256_fingerprint") or r.get("public_key", {}).get("spki_sha256_fingerprint")
            }

        names = list(split_dict.keys())
        fp_overlaps: Dict[str, int] = {}
        spki_overlaps: Dict[str, int] = {}

        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                s1, s2 = names[i], names[j]
                pair_name = f"{s1}_vs_{s2}"
                fp_common = fps_by_split[s1].intersection(fps_by_split[s2])
                spki_common = spkis_by_split[s1].intersection(spkis_by_split[s2])
                fp_overlaps[pair_name] = len(fp_common)
                spki_overlaps[pair_name] = len(spki_common)

        all_clean_fp = all(v == 0 for v in fp_overlaps.values())
        all_clean_spki = all(v == 0 for v in spki_overlaps.values())

        return {
            "fingerprint_leakage_clean": all_clean_fp,
            "public_key_leakage_clean": all_clean_spki,
            "fingerprint_overlaps": fp_overlaps,
            "public_key_overlaps": spki_overlaps,
            "split_sizes": {k: len(v) for k, v in split_dict.items()},
        }

