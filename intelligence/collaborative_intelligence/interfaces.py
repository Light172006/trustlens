"""TrustLens Collaborative Threat Intelligence — Integration Interfaces & Protocols.

Defines typed abstract protocols and lightweight DTOs enabling the backend engineer
to interface with the Collaborative Threat Intelligence module cleanly without
coupling to internal implementation details.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Protocol, runtime_checkable

from collaborative_intelligence.enums import IndicatorStatus
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


@runtime_checkable
class CollaborativeIntelligenceProtocol(Protocol):
    """Authoritative service protocol implemented by the Collaborative Intelligence Engine."""

    def evaluate_report(
        self,
        report: CommunityReportInput,
        existing_reports: Optional[List[CommunityReportInput]] = None,
        reference_time: Optional[datetime] = None,
    ) -> ReportEvaluationResult:
        """Evaluate a single community report submission."""
        ...

    def evaluate_corroboration(
        self,
        reports: List[CommunityReportInput],
        reference_time: Optional[datetime] = None,
    ) -> CorroborationAssessment:
        """Evaluate independent corroboration across a collection of reports."""
        ...

    def find_duplicate_reports(
        self,
        target_report: CommunityReportInput,
        candidate_reports: List[CommunityReportInput],
    ) -> DeduplicationResult:
        """Detect duplicate and related submissions."""
        ...

    def recommend_moderation_action(
        self,
        report: CommunityReportInput,
        validation: ValidationResult,
        deduplication: DeduplicationResult,
        corroboration: CorroborationAssessment,
    ) -> ModerationRecommendation:
        """Produce an explainable moderation recommendation for human queues."""
        ...

    def match_confirmed_indicator(
        self,
        target_url: str,
        indicators: List[ConfirmedIndicator],
        current_time: Optional[datetime] = None,
    ) -> ConfirmedIndicatorMatch:
        """Query incoming scan target against confirmed community intelligence."""
        ...

    def evaluate_indicator_lifecycle(
        self,
        indicator: ConfirmedIndicator,
        current_time: Optional[datetime] = None,
    ) -> IndicatorStatus:
        """Determine whether an indicator is active, disputed, expired, or revoked."""
        ...

