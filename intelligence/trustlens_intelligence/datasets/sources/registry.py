"""TrustLens Intelligence — Dataset Source Registry and Licensing Metadata.

Defines approved public data sources, licensing terms, update frequencies,
rate limits, and attribution requirements for machine learning dataset engineering.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class SourceLicense(StrEnum):
    """Licensing models for dataset sources."""

    PUBLIC_DOMAIN = "public_domain"
    CREATIVE_COMMONS_BY = "cc_by_4.0"
    RESEARCH_ONLY = "research_only"
    OPEN_DATABASE = "odbl"
    PROPRIETARY_TERMS = "proprietary_free_tier"


class LabelCategory(StrEnum):
    """Normalized label taxonomy."""

    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    MALWARE = "malware"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RawRecord:
    """Normalized raw record emitted by a data source adapter before processing."""

    url: str
    source_id: str
    raw_label: str
    timestamp: datetime | None = None
    confidence: float = 1.0
    observed_at: datetime | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    feed_retrieved_at: datetime | None = None
    ingested_at: datetime | None = None
    campaign_id: str | None = None
    original_source_label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)



@dataclass(frozen=True)
class DatasetSourceMeta:
    """Metadata specification for a dataset provider."""

    source_id: str
    name: str
    description: str
    primary_url: str
    download_url: str
    license_type: SourceLicense
    commercial_use_allowed: bool
    research_use_allowed: bool
    attribution_required: bool
    attribution_text: str
    update_frequency: str
    expected_format: str
    default_label: LabelCategory
    rate_limit_per_minute: int = 60
    bulk_download_permitted: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


APPROVED_SOURCES: dict[str, DatasetSourceMeta] = {
    "tranco": DatasetSourceMeta(
        source_id="tranco",
        name="Tranco Top Sites Ranking",
        description="Research-oriented top sites ranking list combining Alexa, Cisco Umbrella, Majestic, and Chrome Floc.",
        primary_url="https://tranco-list.eu/",
        download_url="https://tranco-list.eu/download/daily",
        license_type=SourceLicense.CREATIVE_COMMONS_BY,
        commercial_use_allowed=True,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation (Pochat et al., NDSS 2019)",
        update_frequency="daily",
        expected_format="csv.zip",
        default_label=LabelCategory.LEGITIMATE,
        bulk_download_permitted=True,
        rate_limit_per_minute=30,
    ),
    "openphish": DatasetSourceMeta(
        source_id="openphish",
        name="OpenPhish Community Feed",
        description="Community threat feed identifying active phishing URLs targeting financial, technology, and cloud services.",
        primary_url="https://openphish.com/",
        download_url="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        license_type=SourceLicense.RESEARCH_ONLY,
        commercial_use_allowed=False,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="OpenPhish: Phishing Intelligence Feed (OpenPhish, 2026)",
        update_frequency="hourly",
        expected_format="text/plain",
        default_label=LabelCategory.PHISHING,
        bulk_download_permitted=True,
        rate_limit_per_minute=60,
    ),
    "urlhaus": DatasetSourceMeta(
        source_id="urlhaus",
        name="URLhaus by abuse.ch",
        description="Community project collecting and sharing malicious URLs used for malware distribution.",
        primary_url="https://urlhaus.abuse.ch/",
        download_url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        license_type=SourceLicense.CREATIVE_COMMONS_BY,
        commercial_use_allowed=True,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="URLhaus by abuse.ch (CC BY 4.0)",
        update_frequency="hourly",
        expected_format="csv",
        default_label=LabelCategory.MALWARE,
        bulk_download_permitted=True,
        rate_limit_per_minute=60,
    ),
    "phishtank": DatasetSourceMeta(
        source_id="phishtank",
        name="PhishTank Community Database",
        description="Collaborative clearing house for data and information about phishing on the Internet.",
        primary_url="https://phishtank.org/",
        download_url="http://data.phishtank.com/data/online-valid.csv",
        license_type=SourceLicense.PROPRIETARY_TERMS,
        commercial_use_allowed=False,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="Data provided by PhishTank (OpenDNS/Cisco)",
        update_frequency="hourly",
        expected_format="csv",
        default_label=LabelCategory.PHISHING,
        bulk_download_permitted=True,
        rate_limit_per_minute=10,
    ),
    "benign_deep": DatasetSourceMeta(
        source_id="benign_deep",
        name="Curated Research Benign Deep URLs",
        description="Legitimate web pages with deep paths, query strings, and diverse domain origins to eliminate root-URL bias.",
        primary_url="https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques",
        download_url="https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/1.Benign_list_big_final.csv",
        license_type=SourceLicense.RESEARCH_ONLY,
        commercial_use_allowed=False,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="Curated Benign Deep URL Research Collection (Shreya Gopal et al., 2020)",
        update_frequency="static",
        expected_format="csv",
        default_label=LabelCategory.LEGITIMATE,
        bulk_download_permitted=True,
        rate_limit_per_minute=60,
    ),
    "malware_research": DatasetSourceMeta(
        source_id="malware_research",
        name="Academic Malware URL Collection",
        description="Verified malware distribution and exploit URLs collected across thousands of independent domains.",
        primary_url="https://github.com/matf-ml/ml19-classifying-spam-urls",
        download_url="https://raw.githubusercontent.com/matf-ml/ml19-classifying-spam-urls/master/Malware_dataset.csv",
        license_type=SourceLicense.RESEARCH_ONLY,
        commercial_use_allowed=False,
        research_use_allowed=True,
        attribution_required=True,
        attribution_text="Academic Malware Distribution URL Corpus (MATF ML Research Group, 2019)",
        update_frequency="static",
        expected_format="csv",
        default_label=LabelCategory.MALWARE,
        bulk_download_permitted=True,
        rate_limit_per_minute=60,
    ),
}


class SourceRegistry:
    """Manages verified dataset source configurations and licensing constraints."""

    def __init__(self, sources: dict[str, DatasetSourceMeta] | None = None) -> None:
        self._sources = dict(sources or APPROVED_SOURCES)

    def get(self, source_id: str) -> DatasetSourceMeta | None:
        return self._sources.get(source_id)

    def list_sources(self) -> list[DatasetSourceMeta]:
        return list(self._sources.values())

    def validate_source_permitted(self, source_id: str, commercial: bool = False) -> bool:
        meta = self.get(source_id)
        if not meta:
            return False
        if commercial and not meta.commercial_use_allowed:
            return False
        return meta.research_use_allowed
