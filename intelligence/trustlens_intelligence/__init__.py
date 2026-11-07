"""TrustLens Intelligence Package.

Core threat intelligence, feature extraction, detection rules, risk scoring,
explainability, and machine learning engine for TrustLens.
"""

from trustlens_intelligence.api import (
    TrustLensIntelligenceEngine,
    analyze_website,
    evaluate_threat_feeds,
    extract_features,
    get_default_engine,
)
from trustlens_intelligence.config.constants import (
    CURRENT_SCORING_VERSION,
    FEATURE_SCHEMA_VERSION,
    MODEL_SCHEMA_VERSION,
    FindingCategory,
    FindingSeverity,
    LayerCoverage,
    ProviderName,
    ProviderResultStatus,
    Verdict,
)
from trustlens_intelligence.detection.engine import DetectionEngine
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.explainability.explainer import ExplainabilityEngine
from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.assessment import MLPrediction, ThreatAssessment
from trustlens_intelligence.schemas.evidence import (
    CommunityIntelligenceEvidence,
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    RedirectHopEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.engine import RiskScoringEngine
from trustlens_intelligence.threat_feeds.manager import ThreatIntelManager

__version__ = "1.0.0"

__all__ = [
    # Primary API functions and classes
    "analyze_website",
    "extract_features",
    "evaluate_threat_feeds",
    "TrustLensIntelligenceEngine",
    "get_default_engine",
    # Schemas
    "ScanEvidence",
    "HttpEvidence",
    "RedirectHopEvidence",
    "CookieEvidence",
    "TlsCertificateEvidence",
    "DomainIntelligenceEvidence",
    "ThreatIntelEvidence",
    "CommunityIntelligenceEvidence",
    "Finding",
    "ProviderCheckResult",
    "ExtractedFeatures",
    "MLPrediction",
    "ThreatAssessment",
    # Sub-engines
    "ThreatIntelManager",
    "FeatureExtractor",
    "DetectionEngine",
    "RiskScoringEngine",
    "ExplainabilityEngine",
    "ThreatClassifier",
    # Enums and constants
    "Verdict",
    "FindingCategory",
    "FindingSeverity",
    "ProviderResultStatus",
    "ProviderName",
    "LayerCoverage",
    "CURRENT_SCORING_VERSION",
    "FEATURE_SCHEMA_VERSION",
    "MODEL_SCHEMA_VERSION",
    "__version__",
]

