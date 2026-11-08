"""TrustLens Collaborative Threat Intelligence — Independent Corroboration Engine.

Evaluates independent reports, source diversity, evidence quality, temporal
relevance, and contradiction. Enforces the core rule: report volume alone
never equates to threat confirmation.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import math
from typing import List, Optional, Set

from collaborative_intelligence.abuse_detection import AbuseDetector
from collaborative_intelligence.config import CorroborationConfig, EvidenceEvaluationConfig
from collaborative_intelligence.enums import (
    CorroborationLevel,
    EvidenceStance,
    EvidenceType,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.evidence import EvidenceEvaluator, compute_evidence_fingerprint
from collaborative_intelligence.models import (
    AbuseDetectionResult,
    CommunityReportInput,
    CorroborationAssessment,
    EvidenceItem,
)


class CorroborationEngine:
    """Orchestrates independent corroboration analysis across community reports."""

    def __init__(
        self,
        config: CorroborationConfig | None = None,
        evidence_config: EvidenceEvaluationConfig | None = None,
        abuse_detector: AbuseDetector | None = None,
        evidence_evaluator: EvidenceEvaluator | None = None,
    ) -> None:
        self.config = config or CorroborationConfig()
        self.evidence_config = evidence_config or EvidenceEvaluationConfig()
        self.abuse_detector = abuse_detector or AbuseDetector()
        self.evidence_evaluator = evidence_evaluator or EvidenceEvaluator(config=self.evidence_config)

    def evaluate_corroboration(
        self,
        reports: List[CommunityReportInput],
        reference_time: Optional[datetime] = None,
    ) -> CorroborationAssessment:
        """Evaluate corroboration across a set of reports for a target indicator.

        Args:
            reports: All reports associated with the indicator cluster.
            reference_time: Evaluation anchor time (defaults to current UTC time).

        Returns:
            CorroborationAssessment with qualitative confidence band and reasons.
        """
        ref_time = reference_time or datetime.now(timezone.utc)
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)

        if not reports:
            return CorroborationAssessment(
                corroboration_level=CorroborationLevel.NONE,
                independent_reporter_count=0,
                total_reports_count=0,
                evidence_quality_score=0.0,
                evidence_diversity_score=0.0,
                temporal_relevance_score=0.0,
                conflicting_evidence_count=0,
                abuse_warnings=[],
                supporting_reasons=[],
                weakening_reasons=["No community reports available for this indicator."],
                recommended_review_priority=ReviewPriority.LOW,
            )

        supporting_reasons: list[str] = []
        weakening_reasons: list[str] = []

        # 1. Detect abuse, coordination, and Sybil patterns
        abuse_res: AbuseDetectionResult = self.abuse_detector.analyze_reports(reports)
        abuse_warnings = abuse_res.reasons if abuse_res.is_suspicious else []

        # 2. Determine Genuinely Independent Reporter Sources
        # Group by unique reporter_id first
        reports_by_reporter: dict[str, list[CommunityReportInput]] = defaultdict(list)
        for r in reports:
            reports_by_reporter[r.reporter.reporter_id].append(r)

        raw_reporter_count = len(reports_by_reporter)

        # Disentangle correlated accounts (e.g., shared evidence fingerprints or identical payloads)
        # Connected components clustering for accounts sharing identical evidence
        account_adj: dict[str, set[str]] = {rep_id: set() for rep_id in reports_by_reporter}
        fingerprint_to_accounts: dict[str, set[str]] = defaultdict(set)

        for rep_id, rep_list in reports_by_reporter.items():
            for r in rep_list:
                for item in r.evidence_items:
                    fp = item.fingerprint or compute_evidence_fingerprint(item)
                    fingerprint_to_accounts[fp].add(rep_id)

        for accounts in fingerprint_to_accounts.values():
            if len(accounts) > 1:
                acc_list = list(accounts)
                for i in range(len(acc_list)):
                    for j in range(i + 1, len(acc_list)):
                        account_adj[acc_list[i]].add(acc_list[j])
                        account_adj[acc_list[j]].add(acc_list[i])

        # Find connected components (independent clusters)
        visited = set()
        independent_clusters = 0
        for acc in account_adj:
            if acc not in visited:
                independent_clusters += 1
                queue = [acc]
                visited.add(acc)
                while queue:
                    curr = queue.pop(0)
                    for neighbor in account_adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

        independent_reporter_count = independent_clusters

        if raw_reporter_count > independent_reporter_count:
            weakening_reasons.append(
                f"{raw_reporter_count} reporting accounts collapsed to {independent_reporter_count} "
                "genuinely independent source(s) due to shared evidence or correlated submissions."
            )

        if len(reports) > raw_reporter_count:
            supporting_reasons.append(
                f"Multiple reports ({len(reports)}) submitted across {raw_reporter_count} unique account(s)."
            )

        # 3. Aggregate and evaluate all distinct evidence items
        all_evidence_items: list[EvidenceItem] = []
        seen_fingerprints: set[str] = set()
        for r in reports:
            for item in r.evidence_items:
                fp = item.fingerprint or compute_evidence_fingerprint(item)
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    all_evidence_items.append(item)

        evidence_res = self.evidence_evaluator.evaluate(all_evidence_items)
        conflicting_count = evidence_res.contradicting_count

        if evidence_res.supporting_count > 0:
            supporting_reasons.append(
                f"{evidence_res.supporting_count} distinct supporting evidence item(s) across "
                f"{round(evidence_res.evidence_diversity_score * 3)} categories."
            )
        else:
            weakening_reasons.append("Zero supporting evidence items provided.")

        if conflicting_count > 0:
            weakening_reasons.append(
                f"{conflicting_count} contradictory evidence observation(s) present."
            )

        # 4. Temporal Relevance Decay
        # Calculate age of newest and average report
        ages_days = [(ref_time - r.submitted_at).total_seconds() / 86400.0 for r in reports]
        newest_age_days = max(0.0, min(ages_days))

        # Exponential decay using configured half-life
        decay_factor = math.pow(0.5, newest_age_days / self.config.temporal_decay_half_life_days)
        temporal_relevance = round(max(0.0, min(1.0, decay_factor)), 4)

        if newest_age_days > self.config.stale_evidence_cutoff_days:
            weakening_reasons.append(
                f"Reports are stale (newest report is {newest_age_days:.1f} days old; "
                f"cutoff is {self.config.stale_evidence_cutoff_days} days)."
            )
        elif temporal_relevance >= 0.80:
            supporting_reasons.append(
                f"Observations are fresh and temporally relevant ({newest_age_days:.1f} days old)."
            )

        # 5. Determine Qualitative Corroboration Level
        # Strict Invariants:
        # - High corroboration requires:
        #   * >= 3 independent sources
        #   * Evidence diversity >= 0.60 (at least 2 distinct evidence types)
        #   * Evidence quality >= 0.60
        #   * Zero conflicting evidence
        #   * Temporal relevance >= 0.50
        #   * Abuse risk not HIGH
        # - Medium corroboration requires:
        #   * >= 2 independent sources
        #   * Evidence quality >= 0.35
        #   * Conflicting count == 0 or supporting strongly outweighs
        #   * Abuse risk not HIGH
        # - Low corroboration:
        #   * 1 source with supporting evidence, or 2+ sources with low quality or missing evidence
        # - None:
        #   * 0 supporting evidence, or contradiction dominates
        corroboration_level: CorroborationLevel

        if evidence_res.supporting_count == 0 or (conflicting_count > 0 and conflicting_count >= evidence_res.supporting_count):
            corroboration_level = CorroborationLevel.NONE
            weakening_reasons.append("Contradictory evidence outweighs or negates supporting claims.")
        elif abuse_res.manipulation_risk == "HIGH":
            corroboration_level = CorroborationLevel.LOW
            weakening_reasons.append("Corroboration capped at LOW due to HIGH manipulation/Sybil risk.")
        elif (
            independent_reporter_count >= self.config.min_independent_reporters_high
            and evidence_res.evidence_quality_score >= self.evidence_config.min_quality_for_high_corroboration
            and evidence_res.evidence_diversity_score >= 0.60
            and temporal_relevance >= 0.50
            and conflicting_count == 0
        ):
            corroboration_level = CorroborationLevel.HIGH
            supporting_reasons.append(
                f"High corroboration: {independent_reporter_count} independent sources, "
                f"diverse verified evidence, and zero contradictory observations."
            )
        elif (
            independent_reporter_count >= self.config.min_independent_reporters_medium
            and evidence_res.evidence_quality_score >= self.evidence_config.min_quality_for_medium_corroboration
            and conflicting_count <= 1
        ):
            corroboration_level = CorroborationLevel.MEDIUM
            supporting_reasons.append(
                f"Medium corroboration: {independent_reporter_count} independent sources with corroborating evidence."
            )
        elif evidence_res.supporting_count > 0:
            corroboration_level = CorroborationLevel.LOW
            weakening_reasons.append(
                "Limited corroboration: fewer than 2 independent sources or low evidence quality."
            )
        else:
            corroboration_level = CorroborationLevel.NONE

        # 6. Determine Recommended Review Priority
        has_urgent_category = any(
            r.category in (ThreatCategory.MALWARE, ThreatCategory.PHISHING, ThreatCategory.CREDENTIAL_HARVESTING)
            for r in reports
        )
        if corroboration_level == CorroborationLevel.HIGH and has_urgent_category:
            review_priority = ReviewPriority.URGENT
        elif corroboration_level in (CorroborationLevel.HIGH, CorroborationLevel.MEDIUM):
            review_priority = ReviewPriority.HIGH
        elif abuse_res.manipulation_risk == "HIGH" or conflicting_count > 0:
            review_priority = ReviewPriority.HIGH
        elif corroboration_level == CorroborationLevel.LOW:
            review_priority = ReviewPriority.NORMAL
        else:
            review_priority = ReviewPriority.LOW

        return CorroborationAssessment(
            corroboration_level=corroboration_level,
            independent_reporter_count=independent_reporter_count,
            total_reports_count=len(reports),
            evidence_quality_score=evidence_res.evidence_quality_score,
            evidence_diversity_score=evidence_res.evidence_diversity_score,
            temporal_relevance_score=temporal_relevance,
            conflicting_evidence_count=conflicting_count,
            abuse_warnings=abuse_warnings,
            supporting_reasons=supporting_reasons,
            weakening_reasons=weakening_reasons,
            recommended_review_priority=review_priority,
        )
