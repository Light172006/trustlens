"""TrustLens Collaborative Threat Intelligence — Engine Orchestration Service.

Provides the primary public high-level API consumed by TrustLens backend workers
and moderation workflows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from collaborative_intelligence.config import CollaborativeIntelligenceConfig
from collaborative_intelligence.corroboration import CorroborationEngine
from collaborative_intelligence.deduplication import DeduplicationEngine
from collaborative_intelligence.enums import IndicatorStatus
from collaborative_intelligence.evidence import EvidenceEvaluator
from collaborative_intelligence.indicators import IndicatorMatcher, evaluate_indicator_status
from collaborative_intelligence.moderation import ModerationAdvisor
from collaborative_intelligence.models import (
    CommunityReportInput,
    ConfirmedIndicator,
    ConfirmedIndicatorMatch,
    CorroborationAssessment,
    DeduplicationResult,
    ModerationRecommendation,
    ReportEvaluationResult,
    ValidationResult,
)
from collaborative_intelligence.normalization import NormalizedURL, normalize_url
from collaborative_intelligence.reporter_reliability import evaluate_reporter_reliability
from collaborative_intelligence.validation import validate_report_input


class CollaborativeIntelligenceEngine:
    """Unified Orchestrator for Collaborative Threat Intelligence."""

    def __init__(self, config: CollaborativeIntelligenceConfig | None = None) -> None:
        self.config = config or CollaborativeIntelligenceConfig()
        self.dedup_engine = DeduplicationEngine(
            config=self.config.deduplication,
            norm_config=self.config.normalization,
        )
        self.evidence_evaluator = EvidenceEvaluator(config=self.config.evidence)
        self.corroboration_engine = CorroborationEngine(
            config=self.config.corroboration,
            evidence_config=self.config.evidence,
            evidence_evaluator=self.evidence_evaluator,
        )
        self.moderation_advisor = ModerationAdvisor()
        self.indicator_matcher = IndicatorMatcher(
            norm_config=self.config.normalization,
            lifecycle_config=self.config.lifecycle,
        )

    def evaluate_report(
        self,
        report: CommunityReportInput,
        existing_reports: Optional[List[CommunityReportInput]] = None,
        reference_time: Optional[datetime] = None,
    ) -> ReportEvaluationResult:
        """Perform end-to-end evaluation of a community threat report submission.

        Runs validation, normalization, deduplication, evidence evaluation,
        abuse detection, multi-report corroboration, and moderation recommendation.

        Args:
            report: The newly submitted report.
            existing_reports: Historical or peer reports in the system.
            reference_time: Evaluation anchor time (defaults to now UTC).

        Returns:
            ReportEvaluationResult containing comprehensive findings and recommendations.
        """
        ref_time = reference_time or datetime.now(timezone.utc)
        candidates = existing_reports or []

        # 1. Evaluate and calibrate reporter reliability
        calibrated_reporter = evaluate_reporter_reliability(report.reporter)
        calibrated_report = CommunityReportInput(
            submission_id=report.submission_id,
            original_url=report.original_url,
            category=report.category,
            description=report.description,
            evidence_items=report.evidence_items,
            submitted_at=report.submitted_at,
            reporter=calibrated_reporter,
        )

        # 2. Input validation and URL normalization
        val_res, norm_url = validate_report_input(
            calibrated_report,
            val_config=self.config.validation,
            norm_config=self.config.normalization,
        )

        # 3. Deduplication against existing reports
        dedup_res = self.dedup_engine.evaluate_duplicates(
            target_report=calibrated_report,
            candidate_reports=candidates,
            target_norm=norm_url,
        )

        # 4. Evidence evaluation for the target report's attached items
        ev_res = self.evidence_evaluator.evaluate(calibrated_report.evidence_items)

        # 5. Multi-report Corroboration and Abuse Analysis
        # Include target report and existing related reports for cluster corroboration
        cluster_reports = [calibrated_report] + [
            c for c in candidates if c.submission_id != calibrated_report.submission_id
        ]
        corrob_res = self.corroboration_engine.evaluate_corroboration(
            reports=cluster_reports,
            reference_time=ref_time,
        )

        # 6. Abuse detection specific to the cluster
        abuse_res = self.corroboration_engine.abuse_detector.analyze_reports(cluster_reports)

        # 7. Formulate Explainable Moderation Recommendation
        mod_rec = self.moderation_advisor.advise(
            report=calibrated_report,
            validation=val_res,
            deduplication=dedup_res,
            corroboration=corrob_res,
        )

        canonical_url = norm_url.canonical_url if norm_url else calibrated_report.original_url

        return ReportEvaluationResult(
            submission_id=calibrated_report.submission_id,
            canonical_url=canonical_url,
            validation=val_res,
            deduplication=dedup_res,
            evidence_evaluation=ev_res,
            abuse_detection=abuse_res,
            corroboration=corrob_res,
            moderation_recommendation=mod_rec,
        )

    def evaluate_corroboration(
        self,
        reports: List[CommunityReportInput],
        reference_time: Optional[datetime] = None,
    ) -> CorroborationAssessment:
        """Evaluate corroboration across a collection of reports."""
        return self.corroboration_engine.evaluate_corroboration(
            reports=reports,
            reference_time=reference_time,
        )

    def find_duplicate_reports(
        self,
        target_report: CommunityReportInput,
        candidate_reports: List[CommunityReportInput],
    ) -> DeduplicationResult:
        """Query candidate reports for duplicates and related submissions."""
        return self.dedup_engine.evaluate_duplicates(
            target_report=target_report,
            candidate_reports=candidate_reports,
        )

    def recommend_moderation_action(
        self,
        report: CommunityReportInput,
        validation: ValidationResult,
        deduplication: DeduplicationResult,
        corroboration: CorroborationAssessment,
    ) -> ModerationRecommendation:
        """Generate explainable moderation recommendation."""
        return self.moderation_advisor.advise(
            report=report,
            validation=validation,
            deduplication=deduplication,
            corroboration=corroboration,
        )

    def match_confirmed_indicator(
        self,
        target_url: str,
        indicators: List[ConfirmedIndicator],
        current_time: Optional[datetime] = None,
    ) -> ConfirmedIndicatorMatch:
        """Match an incoming URL against confirmed threat indicators."""
        return self.indicator_matcher.match(
            target_url=target_url,
            indicators=indicators,
            current_time=current_time,
        )

    def evaluate_indicator_lifecycle(
        self,
        indicator: ConfirmedIndicator,
        current_time: Optional[datetime] = None,
    ) -> IndicatorStatus:
        """Evaluate authoritative status of an indicator (confirmed, expired, disputed, revoked)."""
        return evaluate_indicator_status(indicator, current_time=current_time)

