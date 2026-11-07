"""TrustLens Intelligence — Production-Grade Dataset Orchestrator.

Coordinates ingestion, normalization, deduplication, label validation,
allowlisted feature extraction, disjoint domain splitting, Parquet persistence,
and provenance manifest creation.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import pandas as pd

from trustlens_intelligence.datasets.feature_pipeline import BatchFeaturePipeline
from trustlens_intelligence.datasets.processing.deduplicator import DatasetDeduplicator
from trustlens_intelligence.datasets.processing.label_validator import (
    LabelValidator,
    ValidatedSample,
)
from trustlens_intelligence.datasets.processing.normalizer import URLNormalizer
from trustlens_intelligence.datasets.sources.openphish import OpenPhishSource
from trustlens_intelligence.datasets.sources.phishtank import PhishTankSource
from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    RawRecord,
    SourceRegistry,
)
from trustlens_intelligence.datasets.sources.tranco import TrancoSource
from trustlens_intelligence.datasets.sources.urlhaus import URLhausSource
from trustlens_intelligence.datasets.splits.domain_split import DomainSplitter, SplitResult
from trustlens_intelligence.datasets.storage.manifest import (
    DatasetManifest,
    create_manifest_from_dataframe,
)
from trustlens_intelligence.datasets.storage.parquet_store import ParquetStore


@dataclass
class DatasetPipelineResult:
    """Artifacts produced by a completed dataset pipeline execution."""

    full_dataset: pd.DataFrame
    splits: SplitResult
    manifest: DatasetManifest
    output_dir: Path
    file_paths: dict[str, Path]


class DatasetPipeline:
    """End-to-end dataset engineering and preparation pipeline."""

    def __init__(
        self,
        registry: SourceRegistry | None = None,
        normalizer: URLNormalizer | None = None,
        deduplicator: DatasetDeduplicator | None = None,
        validator: LabelValidator | None = None,
        feature_pipeline: BatchFeaturePipeline | None = None,
        splitter: DomainSplitter | None = None,
        store: ParquetStore | None = None,
    ) -> None:
        self.registry = registry or SourceRegistry()
        self.normalizer = normalizer or URLNormalizer()
        self.deduplicator = deduplicator or DatasetDeduplicator(self.normalizer)
        self.validator = validator or LabelValidator()
        self.feature_pipeline = feature_pipeline or BatchFeaturePipeline()
        self.splitter = splitter or DomainSplitter()
        self.store = store or ParquetStore()

    def generate_benchmark_records(
        self,
        samples_per_source: int = 50,
    ) -> list[RawRecord]:
        """Generate deterministic offline mock records across all 4 approved sources."""
        tranco = TrancoSource()
        openphish = OpenPhishSource()
        urlhaus = URLhausSource()
        phishtank = PhishTankSource()

        records: list[RawRecord] = []
        records.extend(tranco.generate_mock_records(count=samples_per_source))
        records.extend(openphish.generate_mock_records(count=samples_per_source))
        records.extend(urlhaus.generate_mock_records(count=samples_per_source))
        records.extend(phishtank.generate_mock_records(count=samples_per_source))
        return records

    def process_records(self, raw_records: list[RawRecord]) -> list[ValidatedSample]:
        """Normalize, deduplicate, and validate raw records into clean samples."""
        self.deduplicator.reset()
        deduped = self.deduplicator.deduplicate_list(raw_records)

        # Group by canonical URL to resolve cross-source conflicts
        grouped: dict[str, list[RawRecord]] = {}
        for r in deduped:
            canon = r.metadata.get("canonical_url", r.url)
            grouped.setdefault(canon, []).append(r)

        validated: list[ValidatedSample] = []
        for records in grouped.values():
            sample = self.validator.resolve_conflicts(records)
            validated.append(sample)

        return validated

    def run_pipeline(
        self,
        raw_records: list[RawRecord],
        output_dir: Path | str,
        dataset_name: str = "trustlens-benchmark",
        version: str = "2.0.0",
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        seed: int = 42,
    ) -> DatasetPipelineResult:
        """Execute the full dataset ingestion, extraction, splitting, and storage workflow."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # 1. Deduplicate, normalize, validate labels
        validated_samples = self.process_records(raw_records)

        # 2. Batch feature extraction with ML Feature Allowlist
        full_df = self.feature_pipeline.extract_dataframe(validated_samples)

        # 3. Domain-aware disjoint splitting
        splits = self.splitter.split(
            full_df,
            train_ratio=train_ratio,
            val_ratio=val_ratio,
            test_ratio=test_ratio,
            seed=seed,
        )

        # 4. Parquet persistence
        files: dict[str, Path] = {
            "full_dataset": out_path / "dataset_full.parquet",
            "train": out_path / "train.parquet",
            "val": out_path / "val.parquet",
            "test": out_path / "test.parquet",
        }

        self.store.write_table(full_df, files["full_dataset"])
        self.store.write_table(splits.train_df, files["train"])
        self.store.write_table(splits.val_df, files["val"])
        self.store.write_table(splits.test_df, files["test"])

        # 5. Manifest creation
        source_attributions = [
            APPROVED_SOURCES[s].attribution_text
            for s in ("tranco", "openphish", "urlhaus", "phishtank")
            if s in APPROVED_SOURCES
        ]

        manifest = create_manifest_from_dataframe(
            df=full_df,
            dataset_name=dataset_name,
            version=version,
            files=files,
            source_attributions=source_attributions,
            extra_metadata={
                "train_samples": len(splits.train_df),
                "val_samples": len(splits.val_df),
                "test_samples": len(splits.test_df),
                "train_domains": len(splits.train_domains),
                "val_domains": len(splits.val_domains),
                "test_domains": len(splits.test_domains),
                "deduplication_stats": {
                    "total_processed": self.deduplicator.stats.total_processed,
                    "total_retained": self.deduplicator.stats.total_retained,
                    "exact_duplicates_dropped": self.deduplicator.stats.exact_duplicates_dropped,
                    "canonical_duplicates_dropped": self.deduplicator.stats.canonical_duplicates_dropped,
                },
            },
        )
        manifest_path = out_path / "manifest.json"
        manifest.save(manifest_path)
        files["manifest"] = manifest_path

        return DatasetPipelineResult(
            full_dataset=full_df,
            splits=splits,
            manifest=manifest,
            output_dir=out_path,
            file_paths=files,
        )

