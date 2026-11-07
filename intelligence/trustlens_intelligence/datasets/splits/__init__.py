"""TrustLens Intelligence — Dataset Splitting Package.

Provides strict domain-aware disjoint splitting (0% domain leakage) and
chronological temporal splitting for production evaluation.
"""

from trustlens_intelligence.datasets.splits.domain_split import (
    DomainSplitter,
    SplitResult,
    verify_zero_domain_leakage,
)
from trustlens_intelligence.datasets.splits.temporal_split import TemporalSplitter

__all__ = [
    "DomainSplitter",
    "SplitResult",
    "TemporalSplitter",
    "verify_zero_domain_leakage",
]

