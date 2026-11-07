"""TrustLens Intelligence Engine — Configuration and Settings."""

from pydantic import BaseModel, Field


class ThreatFeedSettings(BaseModel):
    """Settings for external threat intelligence providers."""

    # OpenPhish settings
    openphish_enabled: bool = Field(default=True, description="Enable OpenPhish feed")
    openphish_feed_url: str = Field(
        default="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        description="Public community feed URL",
    )
    openphish_max_age_hours: float = Field(
        default=13.0,
        description="Maximum allowed feed age before considered stale (hours)",
    )
    openphish_request_timeout_seconds: float = Field(default=5.0)

    # URLhaus settings
    urlhaus_enabled: bool = Field(default=True, description="Enable URLhaus API lookups")
    urlhaus_api_url: str = Field(
        default="https://urlhaus-api.abuse.ch/v1/url/",
        description="URLhaus URL lookup API endpoint",
    )
    urlhaus_auth_key: str | None = Field(
        default=None,
        description="Optional URLhaus Auth-Key header value",
    )
    urlhaus_request_timeout_seconds: float = Field(default=4.0)

    # Cache and Rate Limiting
    provider_cache_ttl_seconds: int = Field(default=3600, description="In-memory cache TTL for provider results")
    max_cache_size: int = Field(default=10000, description="Maximum in-memory cached results before eviction")
    max_retries: int = Field(default=2, description="Max bounded retries for transient HTTP errors")
    backoff_factor: float = Field(default=0.5, description="Exponential backoff factor in seconds")


class ScoringThresholds(BaseModel):
    """Scoring thresholds and rules configuration."""

    # Thresholds
    safe_max_score: int = Field(default=24, description="Maximum score for SAFE verdict")
    suspicious_min_score: int = Field(default=25, description="Minimum score for SUSPICIOUS verdict")
    suspicious_max_score: int = Field(default=74, description="Standard SUSPICIOUS max score")
    malicious_decisive_score: int = Field(default=100, description="Score assigned for decisive malicious indicators")
    community_malicious_min_score: int = Field(default=90, description="Minimum score for multi-confirmed community reports")

    # Caps
    max_total_score: int = Field(default=100)
    cookie_secure_max_points: int = Field(default=6)
    cookie_httponly_max_points: int = Field(default=4)
    cookie_samesite_max_points: int = Field(default=4)


class FeatureExtractionSettings(BaseModel):
    """Settings for feature extraction and heuristics."""

    high_entropy_threshold: float = Field(default=4.3, description="Shannon entropy threshold for high entropy URLs")
    excessive_subdomain_count: int = Field(default=3, description="Subdomain count considered suspicious")
    excessive_redirect_count: int = Field(default=3, description="Redirect count considered suspicious")
    recent_domain_max_days: int = Field(default=30, description="Domain age in days considered newly registered")
    expiring_cert_days: int = Field(default=30, description="Cert expiry days considered expiring soon")


class IntelligenceSettings(BaseModel):
    """Global configuration for the TrustLens intelligence package."""

    feeds: ThreatFeedSettings = Field(default_factory=ThreatFeedSettings)
    scoring: ScoringThresholds = Field(default_factory=ScoringThresholds)
    features: FeatureExtractionSettings = Field(default_factory=FeatureExtractionSettings)
    debug: bool = Field(default=False)

