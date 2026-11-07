"""TrustLens Intelligence — Dataset Provenance and Integrity Manifest.

Computes and records cryptographic checksums, sample distributions,
unique domain metrics, feature schemas, and licensing attributions.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any
import pandas as pd

from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION


def compute_file_sha256(path: Path | str) -> str:
    """Calculate SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class DatasetManifest:
    """Immutable metadata record documenting dataset creation and integrity."""

    dataset_name: str
    version: str
    created_at: str
    total_samples: int
    unique_domains: int
    label_distribution: dict[str, int]
    feature_names: list[str]
    feature_schema_version: str
    files: dict[str, dict[str, Any]]
    source_attributions: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to serializable dictionary."""
        return asdict(self)

    def save(self, path: Path | str) -> Path:
        """Save manifest to a JSON file."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return target_path

    @classmethod
    def load(cls, path: Path | str) -> "DatasetManifest":
        """Load manifest from JSON file."""
        target_path = Path(path)
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


def create_manifest_from_dataframe(
    df: pd.DataFrame,
    dataset_name: str,
    version: str,
    files: dict[str, Path | str],
    source_attributions: list[str],
    domain_column: str = "registrable_domain",
    label_column: str = "label_category",
    feature_schema_version: str = FEATURE_SCHEMA_VERSION,
    extra_metadata: dict[str, Any] | None = None,
) -> DatasetManifest:
    """Generate DatasetManifest directly from an analytical DataFrame and output file paths."""
    total_samples = len(df)
    unique_domains = df[domain_column].nunique() if domain_column in df.columns else 0

    label_counts: dict[str, int] = {}
    if label_column in df.columns:
        label_counts = {str(k): int(v) for k, v in df[label_column].value_counts().items()}

    file_metadata: dict[str, dict[str, Any]] = {}
    for name, path in files.items():
        fpath = Path(path)
        if fpath.exists():
            file_metadata[name] = {
                "path": str(fpath),
                "sha256": compute_file_sha256(fpath),
                "size_bytes": fpath.stat().st_size,
            }

    # Extract non-metadata columns as feature names if present
    non_features = {
        "url",
        "canonical_url",
        "registrable_domain",
        "label_category",
        "binary_label",
        "confidence",
        "source_id",
        "timestamp",
    }
    feature_names = [c for c in df.columns if c not in non_features]

    return DatasetManifest(
        dataset_name=dataset_name,
        version=version,
        created_at=datetime.now(timezone.utc).isoformat(),
        total_samples=total_samples,
        unique_domains=unique_domains,
        label_distribution=label_counts,
        feature_names=feature_names,
        feature_schema_version=feature_schema_version,
        files=file_metadata,
        source_attributions=source_attributions,
        metadata=extra_metadata or {},
    )

