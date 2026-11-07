"""TrustLens Intelligence Features Package."""

from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.features.lexical import calculate_shannon_entropy, extract_lexical_features
from trustlens_intelligence.features.provenance import STANDARD_PROVENANCE_MAP, build_provenance_metadata
from trustlens_intelligence.features.security import extract_security_features
from trustlens_intelligence.features.structural import (
    count_subdomains,
    extract_structural_features,
    has_homoglyphs_or_mixed_scripts,
    is_ip_address,
)

__all__ = [
    "FeatureExtractor",
    "extract_lexical_features",
    "calculate_shannon_entropy",
    "extract_structural_features",
    "count_subdomains",
    "is_ip_address",
    "has_homoglyphs_or_mixed_scripts",
    "extract_security_features",
    "build_provenance_metadata",
    "STANDARD_PROVENANCE_MAP",
]

