"""TrustLens Intelligence — Dataset Sources Package.

Provides registry, metadata, and ingestion adapters for Tranco, OpenPhish,
URLhaus, PhishTank, BenignDeep, and MalwareCatalog.
"""

from trustlens_intelligence.datasets.sources.benign_deep import BenignDeepSource
from trustlens_intelligence.datasets.sources.malware_catalog import MalwareCatalogSource
from trustlens_intelligence.datasets.sources.openphish import OpenPhishSource
from trustlens_intelligence.datasets.sources.phishtank import PhishTankSource
from trustlens_intelligence.datasets.sources.registry import (
    APPROVED_SOURCES,
    DatasetSourceMeta,
    LabelCategory,
    RawRecord,
    SourceLicense,
    SourceRegistry,
)
from trustlens_intelligence.datasets.sources.tranco import TrancoSource
from trustlens_intelligence.datasets.sources.urlhaus import URLhausSource

__all__ = [
    "APPROVED_SOURCES",
    "BenignDeepSource",
    "DatasetSourceMeta",
    "LabelCategory",
    "MalwareCatalogSource",
    "OpenPhishSource",
    "PhishTankSource",
    "RawRecord",
    "SourceLicense",
    "SourceRegistry",
    "TrancoSource",
    "URLhausSource",
]


