"""TrustLens Intelligence — Dataset Processing Package.

Provides URL normalization, multi-tier deduplication, label mapping,
conflict resolution, and machine learning feature allowlisting.
"""

from trustlens_intelligence.datasets.processing.allowlist import (
    ML_INTRINSIC_FEATURE_NAMES,
    THREAT_FEED_EXCLUDED_FEATURES,
    filter_allowlisted_features,
)
from trustlens_intelligence.datasets.processing.deduplicator import (
    DatasetDeduplicator,
    DeduplicationStats,
)
from trustlens_intelligence.datasets.processing.label_validator import (
    LABEL_TAXONOMY_MAP,
    LabelValidator,
    ValidatedSample,
)
from trustlens_intelligence.datasets.processing.normalizer import (
    NormalizedURL,
    URLNormalizer,
    extract_registrable_domain,
)

__all__ = [
    "DatasetDeduplicator",
    "DeduplicationStats",
    "LABEL_TAXONOMY_MAP",
    "LabelValidator",
    "ML_INTRINSIC_FEATURE_NAMES",
    "NormalizedURL",
    "THREAT_FEED_EXCLUDED_FEATURES",
    "URLNormalizer",
    "ValidatedSample",
    "extract_registrable_domain",
    "filter_allowlisted_features",
]

