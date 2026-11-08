"""TrustLens Collaborative Threat Intelligence — Module Public Interface.

Secure, explainable, and production-ready threat intelligence engine evaluating
community-submitted threat reports without platform poisoning or Sybil inflation.
"""

from __future__ import annotations

from collaborative_intelligence.config import (
    AbuseDetectionConfig,
    CollaborativeIntelligenceConfig,
    CorroborationConfig,
    DeduplicationConfig,
    EvidenceEvaluationConfig,
    IndicatorLifecycleConfig,
    NormalizationConfig,
    ValidationConfig,
)
from collaborative_intelligence.enums import (
    AbuseSignalType,
    CorroborationLevel,
    DeduplicationStrength,
    EvidenceStance,
    EvidenceType,
    IndicatorScope,
    IndicatorStatus,
    ModerationAction,
    ReportStatus,
    ReporterReliabilityTier,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.indicators import evaluate_indicator_status
from collaborative_intelligence.interfaces import CollaborativeIntelligenceProtocol
from collaborative_intelligence.models import (
    AbuseDetectionResult,
    CommunityReportInput,
    ConfirmedIndicator,
    ConfirmedIndicatorMatch,
    CorroborationAssessment,
    DeduplicationResult,
    DuplicateMatch,
    EvidenceEvaluationResult,
    EvidenceItem,
    ModerationRecommendation,
    ReportEvaluationResult,
    ReporterMetadata,
    ValidationResult,
)
from collaborative_intelligence.normalization import (
    NormalizedURL,
    URLNormalizationError,
    extract_registrable_domain,
    normalize_url,
)
from collaborative_intelligence.reporter_reliability import evaluate_reporter_reliability
from collaborative_intelligence.service import CollaborativeIntelligenceEngine
from collaborative_intelligence.validation import validate_report_input

__version__ = "1.0.0"

__all__ = [
    # Main Engine
    "CollaborativeIntelligenceEngine",
    "CollaborativeIntelligenceProtocol",
    # Functions
    "normalize_url",
    "validate_report_input",
    "evaluate_reporter_reliability",
    "evaluate_indicator_status",
    "extract_registrable_domain",
    # Configurations
    "CollaborativeIntelligenceConfig",
    "NormalizationConfig",
    "ValidationConfig",
    "DeduplicationConfig",
    "EvidenceEvaluationConfig",
    "CorroborationConfig",
    "AbuseDetectionConfig",
    "IndicatorLifecycleConfig",
    # Enums
    "ThreatCategory",
    "IndicatorScope",
    "ReportStatus",
    "IndicatorStatus",
    "EvidenceType",
    "EvidenceStance",
    "CorroborationLevel",
    "ReviewPriority",
    "ModerationAction",
    "DeduplicationStrength",
    "AbuseSignalType",
    "ReporterReliabilityTier",
    # Models
    "CommunityReportInput",
    "EvidenceItem",
    "ReporterMetadata",
    "NormalizedURL",
    "ValidationResult",
    "DuplicateMatch",
    "DeduplicationResult",
    "EvidenceEvaluationResult",
    "AbuseDetectionResult",
    "CorroborationAssessment",
    "ModerationRecommendation",
    "ConfirmedIndicator",
    "ConfirmedIndicatorMatch",
    "ReportEvaluationResult",
    # Errors
    "URLNormalizationError",
]

