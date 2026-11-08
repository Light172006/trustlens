"""TrustLens Collaborative Threat Intelligence — Moderation Recommendation Advisor.

Generates transparent, explainable recommendations for human moderators.
Enforces the security invariant: no threat indicator is ever automatically
promoted to CONFIRMED without authorized human review and approval.
"""

from __future__ import annotations

from typing import List

from collaborative_intelligence.enums import (
    CorroborationLevel,
    ModerationAction,
    ReportStatus,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    CommunityReportInput,
    CorroborationAssessment,
    DeduplicationResult,
    ModerationRecommendation,
    ValidationResult,
)


class ModerationAdvisor:
    """Advises moderation queues on report triage, deduplication, and escalation."""

    def advise(
        self,
        report: CommunityReportInput,
        validation: ValidationResult,
        deduplication: DeduplicationResult,
        corroboration: CorroborationAssessment,
    ) -> ModerationRecommendation:
        """Formulate an explainable moderation recommendation.

        Args:
            report: The submitted report.
            validation: Validation check result.
            deduplication: Deduplication check result.
            corroboration: Multi-report corroboration assessment.

        Returns:
            ModerationRecommendation with recommended action, queue priority, and audit reasons.
        """
        reasons: list[str] = []
        warnings: list[str] = []

        # 1. Invalid input check
        if not validation.is_valid:
            reasons.extend(validation.errors)
            return ModerationRecommendation(
                recommended_action=ModerationAction.REQUEST_MORE_EVIDENCE,
                recommended_report_status=ReportStatus.REJECTED,
                review_priority=ReviewPriority.LOW,
                reasons=[f"Submission failed input validation: {'; '.join(validation.errors)}"],
                warnings=validation.warnings,
                requires_human_approval=True,
            )

        # 2. Abuse / Coordinated Campaign Alert (Security Priority over Duplicate Grouping)
        if corroboration.abuse_warnings:
            warnings.extend(corroboration.abuse_warnings)
            reasons.append(
                "Suspicious reporting pattern or coordination detected. Flagged for fraud/abuse investigation."
            )
            return ModerationRecommendation(
                recommended_action=ModerationAction.SUSPECT_ABUSE,
                recommended_report_status=ReportStatus.UNDER_REVIEW,
                review_priority=ReviewPriority.HIGH,
                reasons=reasons,
                warnings=warnings,
                requires_human_approval=True,
            )

        # 3. Conflicting Evidence Warning (Contradictions require manual review)
        if corroboration.conflicting_evidence_count > 0:
            warnings.append(
                f"{corroboration.conflicting_evidence_count} conflicting or contradictory "
                "observation(s) detected. Requires senior human review to avoid false positive."
            )
            reasons.append("Contradictory evidence requires manual verification before any action.")
            return ModerationRecommendation(
                recommended_action=ModerationAction.QUEUE_FOR_REVIEW,
                recommended_report_status=ReportStatus.UNDER_REVIEW,
                review_priority=ReviewPriority.HIGH,
                reasons=reasons,
                warnings=warnings,
                requires_human_approval=True,
            )

        # 4. Duplicate submission handling (Clean, non-abusive duplicates)
        if deduplication.is_duplicate:
            primary_id = deduplication.primary_submission_id or "earlier_submission"
            reasons.append(
                f"Report is a canonical duplicate of existing submission '{primary_id}'. "
                "Recommended for automatic duplicate grouping while preserving reporter attribution."
            )
            return ModerationRecommendation(
                recommended_action=ModerationAction.AUTO_FLAG_DUPLICATE,
                recommended_report_status=ReportStatus.DUPLICATE,
                review_priority=ReviewPriority.LOW,
                reasons=reasons,
                warnings=[],
                requires_human_approval=True,
            )

        # 5. Insufficient Evidence
        if not report.evidence_items or corroboration.evidence_quality_score == 0.0:
            warnings.append("Report contains zero verifiable supporting evidence.")
            reasons.append("Community claim lacks technical proof or verifiable telemetry.")
            return ModerationRecommendation(
                recommended_action=ModerationAction.REQUEST_MORE_EVIDENCE,
                recommended_report_status=ReportStatus.PENDING,
                review_priority=ReviewPriority.LOW,
                reasons=reasons,
                warnings=warnings,
                requires_human_approval=True,
            )

        # 6. High Corroboration / Severe Threat -> Escalate Urgent
        is_severe_threat = report.category in (
            ThreatCategory.MALWARE,
            ThreatCategory.PHISHING,
            ThreatCategory.CREDENTIAL_HARVESTING,
        )
        if corroboration.corroboration_level == CorroborationLevel.HIGH:
            reasons.append(
                f"High independent corroboration ({corroboration.independent_reporter_count} sources) "
                f"with diverse verified evidence for {report.category.value}."
            )
            priority = ReviewPriority.URGENT if is_severe_threat else ReviewPriority.HIGH
            return ModerationRecommendation(
                recommended_action=ModerationAction.ESCALATE_URGENT if is_severe_threat else ModerationAction.QUEUE_FOR_REVIEW,
                recommended_report_status=ReportStatus.UNDER_REVIEW,
                review_priority=priority,
                reasons=reasons,
                warnings=warnings,
                requires_human_approval=True,
            )

        # 7. Medium Corroboration -> Queue for standard or high review
        if corroboration.corroboration_level == CorroborationLevel.MEDIUM:
            reasons.append(
                f"Medium corroboration ({corroboration.independent_reporter_count} sources) "
                "with verified supporting evidence."
            )
            return ModerationRecommendation(
                recommended_action=ModerationAction.QUEUE_FOR_REVIEW,
                recommended_report_status=ReportStatus.UNDER_REVIEW,
                review_priority=ReviewPriority.HIGH if is_severe_threat else ReviewPriority.NORMAL,
                reasons=reasons,
                warnings=warnings,
                requires_human_approval=True,
            )

        # 8. Low Corroboration -> Standard Pending Queue
        reasons.append(
            "Single report or low evidence quality. Queued for normal review pending additional corroboration."
        )
        return ModerationRecommendation(
            recommended_action=ModerationAction.QUEUE_FOR_REVIEW,
            recommended_report_status=ReportStatus.PENDING,
            review_priority=ReviewPriority.NORMAL,
            reasons=reasons,
            warnings=warnings,
            requires_human_approval=True,
        )

