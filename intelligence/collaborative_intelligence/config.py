"""TrustLens Collaborative Threat Intelligence — Engine Configuration & Policy.

Centralizes all operational thresholds, abuse detection windows, corroboration
weights, field bounds, and indicator lifecycle policies. No magic constants
are hardcoded in core logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set


@dataclass(frozen=True)
class NormalizationConfig:
    """Settings governing URL normalization and indicator extraction."""

    allowed_schemes: Set[str] = field(default_factory=lambda: {"http", "https"})
    max_url_length: int = 2048
    max_host_length: int = 253
    max_path_length: int = 1024
    max_query_length: int = 1024
    strip_default_ports: bool = True
    strip_fragments: bool = True
    strip_userinfo_from_canonical: bool = True
    preserve_query_order_deterministically: bool = True
    max_redirect_depth_trace: int = 10


@dataclass(frozen=True)
class ValidationConfig:
    """Input validation and DoS defense limits."""

    min_url_length: int = 3
    max_url_length: int = 2048
    max_description_length: int = 4096
    max_evidence_items: int = 25
    max_evidence_description_length: int = 2048
    max_evidence_source_length: int = 256
    max_reporter_id_length: int = 128


@dataclass(frozen=True)
class DeduplicationConfig:
    """Duplicate detection and clustering rules."""

    similarity_threshold: float = 0.85
    min_exact_match_for_grouping: bool = True
    cluster_window_days: int = 30
    distinguish_subdomains_by_default: bool = True
    allow_path_variant_grouping: bool = True


@dataclass(frozen=True)
class EvidenceEvaluationConfig:
    """Weights and thresholds for evidence provenance and credibility."""

    # Weights by evidence type (0.0 to 1.0)
    type_weights: dict[str, float] = field(
        default_factory=lambda: {
            "ANALYZER_FINDING": 0.95,
            "THREAT_FEED_MATCH": 0.90,
            "SECURITY_RESEARCH": 0.85,
            "CERTIFICATE_OBSERVATION": 0.80,
            "REDIRECT_TRACE": 0.75,
            "DNS_OBSERVATION": 0.70,
            "PHISHING_PAGE_ARTIFACT": 0.65,
            "BROWSER_WARNING": 0.60,
            "SCREENSHOT": 0.40,
            "USER_EXPLANATION": 0.25,
        }
    )
    unverified_penalty: float = 0.50
    contradiction_weight_multiplier: float = 1.50
    min_quality_for_high_corroboration: float = 0.60
    min_quality_for_medium_corroboration: float = 0.35


@dataclass(frozen=True)
class CorroborationConfig:
    """Thresholds and independent corroboration rules."""

    min_independent_reporters_medium: int = 2
    min_independent_reporters_high: int = 3
    min_evidence_diversity_categories_high: int = 2
    temporal_decay_half_life_days: float = 14.0
    stale_evidence_cutoff_days: int = 90
    max_burst_window_seconds: int = 600
    burst_report_count_threshold: int = 4


@dataclass(frozen=True)
class AbuseDetectionConfig:
    """Heuristics for identifying coordinated campaigns and Sybil rings."""

    burst_window_seconds: int = 300
    burst_threshold_per_host: int = 3
    identical_payload_similarity_threshold: float = 0.92
    min_reporters_for_sybil_check: int = 2
    max_account_creation_window_hours: int = 24
    untested_account_penalty: float = 0.30


@dataclass(frozen=True)
class IndicatorLifecycleConfig:
    """Indicator scope, expiration, and dispute handling policies."""

    default_indicator_ttl_days: int = 90
    high_confidence_ttl_days: int = 180
    dispute_grace_period_days: int = 7
    # Requirements for promoting indicator scope from EXACT_URL to HOST:
    # Requires at least 3 distinct malicious paths or root compromise evidence
    min_distinct_paths_for_host_scope: int = 3
    # Requirements for DOMAIN scope:
    # Requires verified domain-wide compromise (e.g. DNS hijack or wildcard record)
    require_domain_compromise_evidence: bool = True


@dataclass(frozen=True)
class CollaborativeIntelligenceConfig:
    """Master configuration aggregating all sub-policies."""

    normalization: NormalizationConfig = field(default_factory=NormalizationConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    deduplication: DeduplicationConfig = field(default_factory=DeduplicationConfig)
    evidence: EvidenceEvaluationConfig = field(default_factory=EvidenceEvaluationConfig)
    corroboration: CorroborationConfig = field(default_factory=CorroborationConfig)
    abuse: AbuseDetectionConfig = field(default_factory=AbuseDetectionConfig)
    lifecycle: IndicatorLifecycleConfig = field(default_factory=IndicatorLifecycleConfig)

