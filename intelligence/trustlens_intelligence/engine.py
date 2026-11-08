"""TrustLens Intelligence — Public Engine Module for backend integration compatibility.

Exposes primary entrypoint functions and the unified engine class expected by the backend client.
"""

from trustlens_intelligence.api import (
    TrustLensIntelligenceEngine,
    analyze_website,
    evaluate_threat_feeds,
    extract_features,
    get_default_engine,
)

__all__ = [
    "TrustLensIntelligenceEngine",
    "analyze_website",
    "evaluate_threat_feeds",
    "extract_features",
    "get_default_engine",
]

