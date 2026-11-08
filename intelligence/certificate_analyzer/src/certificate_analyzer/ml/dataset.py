"""Dataset loader and split manager for Certificate ML training and evaluation."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

import pandas as pd
import pyarrow.parquet as pq


class CertificateMLDataset:
    """Loads and formats certificate datasets for ML training from Parquet or JSONL."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("intelligence/certificate_dataset/data")
        self.normalized_parquet = self.data_dir / "normalized" / "normalized_certificates.parquet"
        self.labels_parquet = self.data_dir / "labeled" / "certificate_labels.parquet"
        self.splits_dir = self.data_dir / "splits"

    def load_split_records(self, split_type: str = "spki_disjoint") -> Dict[str, List[Dict[str, Any]]]:
        """Loads train, val, and test partitions for a given split strategy.

        Args:
            split_type: 'spki_disjoint', 'fingerprint_disjoint', or 'chronological'
        """
        result: Dict[str, List[Dict[str, Any]]] = {}
        for partition in ["train", "val", "test"]:
            file_name = f"{partition}_{split_type}.jsonl"
            split_path = self.splits_dir / file_name
            if not split_path.exists():
                raise FileNotFoundError(f"Split file not found: {split_path}")

            records = []
            with open(split_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))
            result[partition] = records

        return result

    def get_labels_map(self) -> Dict[str, Dict[str, str]]:
        """Maps SHA-256 fingerprint to its dictionary of security labels."""
        labels_jsonl = self.data_dir / "labeled" / "certificate_labels.jsonl"
        labels_map: Dict[str, Dict[str, str]] = {}
        if labels_jsonl.exists():
            with open(labels_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        fp = r.get("certificate_sha256_fingerprint") or r.get("certificate_sha256")
                        lbls = r.get("labels")
                        if fp and isinstance(lbls, dict):
                            labels_map[fp] = lbls
            return labels_map

        # Fallback to flattened parquet
        labels_table = pq.read_table(self.labels_parquet)
        df_labels = labels_table.to_pandas()
        fp_col = "certificate_sha256_fingerprint" if "certificate_sha256_fingerprint" in df_labels.columns else "certificate_sha256"
        for _, row in df_labels.iterrows():
            fp = row.get(fp_col)
            lbls = {
                col.replace("labels.", ""): row[col]
                for col in df_labels.columns
                if col.startswith("labels.")
            }
            if fp:
                labels_map[fp] = lbls
        return labels_map

    @classmethod
    def extract_tabular_features(
        cls,
        records: List[Dict[str, Any]],
        labels_map: Dict[str, Dict[str, str]],
        target_label: str = "POLICY_COMPLIANT",
    ) -> pd.DataFrame:
        """Extracts strictly raw structural features and target binary label.

        Guarantees zero target leakage by rejecting any rule output or finding codes.
        """
        rows = []
        for r in records:
            fp = r.get("sha256_fingerprint")
            pk = r.get("public_key") or {}
            dom = r.get("domain_identity") or {}
            exts = r.get("extensions") or {}

            # Raw numeric and categorical structural parameters
            key_algo = pk.get("algorithm") or "UNKNOWN"
            key_size = pk.get("key_size_bits") or 0
            ec_curve = pk.get("ec_curve") or "none"
            sig_algo = r.get("signature_algorithm") or "UNKNOWN"
            val_days = r.get("validity_duration_days") or 0.0

            sans = dom.get("subject_alternative_names") or []
            san_count = len(sans)
            is_wildcard = 1 if dom.get("is_wildcard") else 0

            # Extension counts & indicators
            sct_ext = exts.get("signed_certificate_timestamps")
            has_scts = 1 if sct_ext else 0
            sct_count = len(sct_ext) if isinstance(sct_ext, list) else 0

            # Count non-empty extensions
            ext_count = sum(1 for k, v in exts.items() if v is not None and v != [] and v != {})
            
            # Key usages & EKUs
            ku = exts.get("key_usage")
            ku_count = len(ku) if isinstance(ku, list) else (sum(1 for v in ku.values() if v) if isinstance(ku, dict) else 0)
            
            eku = exts.get("extended_key_usage")
            eku_count = len(eku) if isinstance(eku, list) else 0

            is_ca = 1 if (r.get("is_ca") or exts.get("basic_constraints", {}).get("is_ca")) else 0
            is_self_signed = 1 if r.get("is_self_signed") else 0

            # Subject attribute length
            subj_dn = r.get("subject_dn") or ""
            subj_len = len(subj_dn)

            # Target label
            lbl_dict = labels_map.get(fp, {})
            raw_target = lbl_dict.get(target_label)

            # Map target: PASS -> 1 (compliant), FAIL -> 0 (non-compliant)
            if raw_target == "PASS":
                target = 1
            elif raw_target == "FAIL":
                target = 0
            else:
                # Skip unverified or unknown label entries
                continue

            rows.append({
                "fingerprint": fp,
                "spki": r.get("spki_sha256_fingerprint") or pk.get("spki_sha256_fingerprint", "none"),
                "key_algorithm": str(key_algo),
                "key_size_bits": float(key_size),
                "ec_curve": str(ec_curve),
                "signature_algorithm": str(sig_algo),
                "validity_duration_days": float(val_days),
                "san_count": int(san_count),
                "is_wildcard": int(is_wildcard),
                "has_scts": int(has_scts),
                "sct_count": int(sct_count),
                "extension_count": int(ext_count),
                "key_usage_count": int(ku_count),
                "extended_key_usage_count": int(eku_count),
                "is_ca": int(is_ca),
                "is_self_signed": int(is_self_signed),
                "subject_dn_length": int(subj_len),
                "target": int(target),
            })

        return pd.DataFrame(rows)
