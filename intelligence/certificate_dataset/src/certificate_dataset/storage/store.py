"""Data storage, Parquet persistence, streaming JSONL, and checksum verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd


class DatasetStorage:
    """Manages raw blobs, Parquet analytical tables, streaming JSONL, and SHA-256 manifests."""

    def __init__(self, base_data_dir: Optional[Path] = None):
        if base_data_dir is None:
            base_data_dir = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "data"
            )
        self.base_dir = Path(base_data_dir)
        self.raw_dir = self.base_dir / "raw"
        self.normalized_dir = self.base_dir / "normalized"
        self.labeled_dir = self.base_dir / "labeled"
        self.endpoint_dir = self.base_dir / "endpoint_observations"
        self.revocation_dir = self.base_dir / "revocation"
        self.trust_stores_dir = self.base_dir / "trust_stores"
        self.splits_dir = self.base_dir / "splits"
        self.manifests_dir = self.base_dir / "manifests"
        self.quarantine_dir = self.base_dir / "quarantine"

        # Ensure all directories exist
        for d in [
            self.raw_dir,
            self.normalized_dir,
            self.labeled_dir,
            self.endpoint_dir,
            self.revocation_dir,
            self.trust_stores_dir,
            self.splits_dir,
            self.manifests_dir,
            self.quarantine_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)

    def save_raw_der(self, der_bytes: bytes, sha256_fp: str) -> Path:
        """Persists raw DER blob named by sha256 fingerprint."""
        dest = self.raw_dir / f"{sha256_fp}.der"
        with open(dest, "wb") as f:
            f.write(der_bytes)
        return dest

    def save_jsonl(self, records: List[Dict[str, Any]], destination_file: Path) -> Path:
        """Saves records to JSON Lines format."""
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        with open(destination_file, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        return destination_file

    def read_jsonl(self, source_file: Path) -> List[Dict[str, Any]]:
        """Reads records from JSON Lines format."""
        records = []
        if not source_file.exists():
            return records
        with open(source_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    records.append(json.loads(line_str))
        return records

    def save_parquet(self, records: List[Dict[str, Any]], destination_file: Path) -> Path:
        """Saves analytical records to columnar Parquet format using pandas and pyarrow."""
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        df = pd.json_normalize(records)
        df.to_parquet(destination_file, engine="pyarrow", index=False)
        return destination_file

    def quarantine_failed_record(self, raw_input: bytes, error_message: str, identifier: str) -> Path:
        """Quarantines malformed or unparseable certificate input."""
        q_path = self.quarantine_dir / f"{identifier}.quarantine.json"
        payload = {
            "identifier": identifier,
            "error_message": error_message,
            "raw_hex": raw_input.hex(),
            "byte_length": len(raw_input),
        }
        with open(q_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return q_path

    @staticmethod
    def compute_sha256_checksum(file_path: Path) -> str:
        """Calculates SHA-256 digest of any dataset file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

