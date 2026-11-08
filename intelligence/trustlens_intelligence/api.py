"""TrustLens Intelligence — Public Interface and API Entrypoints.

Provides the primary public functions and engine class consumed by backend workers and services.
"""

from datetime import datetime, timezone
import logging
from typing import Any

from trustlens_intelligence.config.constants import (
    CURRENT_SCORING_VERSION,
    LayerCoverage,
    ProviderName,
    ProviderResultStatus,
    Verdict,
)
from trustlens_intelligence.config.settings import IntelligenceSettings
from trustlens_intelligence.detection.engine import DetectionEngine
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.explainability.explainer import ExplainabilityEngine
from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.assessment import ThreatAssessment
from trustlens_intelligence.schemas.evidence import ScanEvidence, ThreatIntelEvidence
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.engine import RiskScoringEngine
from trustlens_intelligence.threat_feeds.manager import ThreatIntelManager

logger = logging.getLogger("trustlens.intelligence.api")


class TrustLensIntelligenceEngine:
    """Unified TrustLens Intelligence Engine.

    Interprets normalized website scan observations, evaluates threat feeds,
    extracts deterministic features, executes detection rules, calculates
    versioned risk scores, and generates explainable assessment reports.
    """

    def __init__(
        self,
        settings: IntelligenceSettings | None = None,
        threat_manager: ThreatIntelManager | None = None,
        detection_engine: DetectionEngine | None = None,
        scoring_engine: RiskScoringEngine | None = None,
        explainer: ExplainabilityEngine | None = None,
        classifier: ThreatClassifier | None = None,
    ) -> None:
        self.settings = settings or IntelligenceSettings()
        self.threat_manager = threat_manager or ThreatIntelManager(settings=self.settings.feeds)
        self.feature_extractor = FeatureExtractor()
        self.detection_engine = detection_engine or DetectionEngine()
        self.scoring_engine = scoring_engine or RiskScoringEngine()
        self.explainer = explainer or ExplainabilityEngine()
        self.classifier = classifier or (
            ThreatClassifier.load_default()
            if ThreatClassifier.DEFAULT_ARTIFACT_PATH.exists()
            else ThreatClassifier()
        )

    def extract_features(self, evidence: ScanEvidence) -> ExtractedFeatures:
        """Extract typed feature vector from normalized evidence."""
        return self.feature_extractor.extract(evidence)

    def evaluate_threat_feeds(
        self,
        url: str,
        is_sensitive: bool = False,
    ) -> list[ProviderCheckResult]:
        """Query configured threat intelligence providers for the URL."""
        return self.threat_manager.query_all(url, is_sensitive=is_sensitive)

    def analyze(
        self,
        evidence: ScanEvidence | Any,
        query_providers: bool = False,
        is_scan_failed: bool = False,
    ) -> ThreatAssessment:
        """Execute full threat intelligence analysis on normalized scan evidence.

        Args:
            evidence: Normalized scan observations supplied by the backend.
            query_providers: If True, executes queries against configured threat feeds
                and injects matches into the evidence model. If False, interprets
                threat feed checks already present in `evidence.threat_intelligence`.
            is_scan_failed: If True, indicates an internal scan worker failure.

        Returns:
            ThreatAssessment with verdict, score, confidence, findings, coverage, and summary.
        """
        if not isinstance(evidence, ScanEvidence):
            evidence = ScanEvidence.model_validate(evidence)

        target_url = evidence.canonical_url or evidence.original_url
        provider_checks: list[ProviderCheckResult] = []

        # 1. Threat Intelligence Resolution
        if query_providers:
            provider_checks = self.evaluate_threat_feeds(target_url, is_sensitive=evidence.is_sensitive)
            # Synchronize matches into evidence
            openphish_res = next((p for p in provider_checks if p.provider == ProviderName.OPENPHISH.value), None)
            urlhaus_res = next((p for p in provider_checks if p.provider == ProviderName.URLHAUS.value), None)

            if evidence.threat_intelligence is None:
                evidence.threat_intelligence = ThreatIntelEvidence()

            if openphish_res:
                evidence.threat_intelligence.openphish_match = openphish_res.matched
                evidence.threat_intelligence.openphish_status = openphish_res.result_status.value
            if urlhaus_res:
                evidence.threat_intelligence.urlhaus_match = urlhaus_res.matched
                evidence.threat_intelligence.urlhaus_status = urlhaus_res.result_status.value
                evidence.threat_intelligence.urlhaus_url_status = urlhaus_res.details.get("url_status")
        elif evidence.threat_intelligence:
            # Build provider checks from evidence if not querying providers directly
            if evidence.threat_intelligence.openphish_status:
                provider_checks.append(
                    ProviderCheckResult(
                        provider="openphish",
                        result_status=ProviderResultStatus(evidence.threat_intelligence.openphish_status),
                        matched=bool(evidence.threat_intelligence.openphish_match),
                    )
                )
            if evidence.threat_intelligence.urlhaus_status:
                provider_checks.append(
                    ProviderCheckResult(
                        provider="urlhaus",
                        result_status=ProviderResultStatus(evidence.threat_intelligence.urlhaus_status),
                        matched=bool(evidence.threat_intelligence.urlhaus_match),
                        details={"url_status": evidence.threat_intelligence.urlhaus_url_status},
                    )
                )

        if evidence.community_intelligence is not None:
            comm = evidence.community_intelligence
            distinct = (
                comm.distinct_reporter_count
                if comm.distinct_reporter_count > 0
                else (
                    len({r.get("reporter_id") for r in comm.reports if r.get("reporter_id")})
                    if comm.reports
                    else comm.confirmed_report_count
                )
            )
            comm_matched = bool(comm.confirmed_report_count >= 2 and distinct >= 2)
            provider_checks.append(
                ProviderCheckResult(
                    provider="community",
                    result_status=ProviderResultStatus.MATCH if comm_matched else ProviderResultStatus.NO_MATCH,
                    matched=comm_matched,
                    details={
                        "confirmed_report_count": comm.confirmed_report_count,
                        "distinct_reporter_count": distinct,
                    },
                )
            )

        # 2. Feature Extraction
        features = self.feature_extractor.extract(evidence)

        # 3. Detection Rule Evaluation
        detection_result = self.detection_engine.evaluate(evidence, features)

        # 4. Deterministic Risk Scoring
        score_result = self.scoring_engine.score(
            evidence=evidence,
            findings=detection_result.findings,
            provider_checks=provider_checks,
            has_decisive_malicious=detection_result.has_decisive_malicious,
            is_scan_failed=is_scan_failed,
        )

        # 5. Enforce Explainability Invariants
        findings = self.explainer.ensure_explainability_invariants(
            verdict=score_result.verdict,
            findings=detection_result.findings,
            coverage=score_result.coverage,
        )

        # 6. Executive Narrative Summary
        summary = self.explainer.build_summary(
            verdict=score_result.verdict,
            risk_score=score_result.score,
            findings=findings,
            coverage=score_result.coverage,
        )

        # 7. Optional Machine Learning Inference
        ml_prediction = None
        if self.classifier.is_loaded:
            ml_prediction = self.classifier.predict(features)

        return ThreatAssessment(
            scan_id=evidence.scan_id,
            verdict=score_result.verdict,
            risk_score=score_result.score,
            confidence=score_result.confidence,
            scoring_version=CURRENT_SCORING_VERSION,
            checks_completed=score_result.checks_completed,
            coverage=score_result.coverage,
            findings=findings,
            provider_checks=provider_checks,
            features=features,
            ml_prediction=ml_prediction,
            summary=summary,
            evaluated_at=datetime.now(timezone.utc),
        )


# ==============================================================================
# FUNCTIONAL PUBLIC APIS
# ==============================================================================

_GLOBAL_ENGINE: TrustLensIntelligenceEngine | None = None


def get_default_engine() -> TrustLensIntelligenceEngine:
    """Return singleton instance of the intelligence engine."""
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = TrustLensIntelligenceEngine()
    return _GLOBAL_ENGINE


def analyze_website(
    evidence: ScanEvidence,
    query_providers: bool = False,
    is_scan_failed: bool = False,
) -> ThreatAssessment:
    """Public convenience function to analyze website evidence.

    Args:
        evidence: Normalized scan observations.
        query_providers: Whether to trigger provider queries.
        is_scan_failed: Flag for failed scan workers.

    Returns:
        Structured ThreatAssessment.
    """
    engine = get_default_engine()
    return engine.analyze(
        evidence=evidence,
        query_providers=query_providers,
        is_scan_failed=is_scan_failed,
    )


def extract_features(evidence: ScanEvidence) -> ExtractedFeatures:
    """Public convenience function to extract features from evidence."""
    engine = get_default_engine()
    return engine.extract_features(evidence)


def evaluate_threat_feeds(
    url: str,
    is_sensitive: bool = False,
) -> list[ProviderCheckResult]:
    """Public convenience function to query configured threat feeds."""
    engine = get_default_engine()
    return engine.evaluate_threat_feeds(url, is_sensitive=is_sensitive)

