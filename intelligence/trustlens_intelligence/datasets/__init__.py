"""TrustLens Intelligence — Production-Scale Dataset Engineering Package.

Provides high-scale ingestion, RFC 3986 normalization, domain-aware deduplication,
label taxonomy mapping, ML feature allowlisting, streaming Parquet storage,
and disjoint domain splitting.
"""

from trustlens_intelligence.datasets.feature_pipeline import BatchFeaturePipeline
from trustlens_intelligence.datasets.pipeline import (
    DatasetPipeline,
    DatasetPipelineResult,
)
from trustlens_intelligence.datasets.processing import (
    DatasetDeduplicator,
    LabelValidator,
    ML_INTRINSIC_FEATURE_NAMES,
    THREAT_FEED_EXCLUDED_FEATURES,
    URLNormalizer,
    ValidatedSample,
    filter_allowlisted_features,
)
from trustlens_intelligence.datasets.sources import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    OpenPhishSource,
    PhishTankSource,
    RawRecord,
    SourceLicense,
    SourceRegistry,
    TrancoSource,
    URLhausSource,
)
from trustlens_intelligence.datasets.splits import (
    DomainSplitter,
    SplitResult,
    TemporalSplitter,
    verify_zero_domain_leakage,
)
from trustlens_intelligence.datasets.storage import (
    DatasetManifest,
    ParquetStore,
    create_manifest_from_dataframe,
)

__all__ = [
    "APPROVED_SOURCES",
    "BatchFeaturePipeline",
    "DatasetDeduplicator",
    "DatasetManifest",
    "DatasetPipeline",
    "DatasetPipelineResult",
    "DatasetSourceMeta",
    "DomainSplitter",
    "LabelCategory",
    "LabelValidator",
    "ML_INTRINSIC_FEATURE_NAMES",
    "OpenPhishSource",
    "ParquetStore",
    "PhishTankSource",
    "RawRecord",
    "SourceLicense",
    "SourceRegistry",
    "SplitResult",
    "THREAT_FEED_EXCLUDED_FEATURES",
    "TemporalSplitter",
    "TrancoSource",
    "URLNormalizer",
    "URLhausSource",
    "ValidatedSample",
    "create_manifest_from_dataframe",
    "filter_allowlisted_features",
    "verify_zero_domain_leakage",
]

