"""TrustLens Collaborative Threat Intelligence — Reporter Reliability Evaluation.

Evaluates reporting account track record using conservative, anti-farming heuristics.
Maintains strict separation between reporter reliability and threat confidence.
"""

from __future__ import annotations

from collaborative_intelligence.enums import ReporterReliabilityTier
from collaborative_intelligence.models import ReporterMetadata


def evaluate_reporter_reliability(metadata: ReporterMetadata) -> ReporterMetadata:
    """Evaluate account track record and compute reliability score and tier.

    Invariants:
    1. New accounts start with a neutral baseline (0.50), not penalized or assumed malicious.
    2. Account age alone does not confer high reliability without verified history.
    3. Merely submitting high volumes of reports does not increase reliability (anti-farming).
    4. Restricted accounts receive a restricted tier and reduced score.
    5. High reliability never bypasses evidence requirements.
    """
    if metadata.is_restricted:
        return ReporterMetadata(
            reporter_id=metadata.reporter_id,
            account_age_days=metadata.account_age_days,
            previous_accepted_reports=metadata.previous_accepted_reports,
            previous_rejected_reports=metadata.previous_rejected_reports,
            is_trusted=metadata.is_trusted,
            is_restricted=True,
            calculated_reliability_score=0.10,
            assessed_tier=ReporterReliabilityTier.RESTRICTED,
        )

    accepted = metadata.previous_accepted_reports
    rejected = metadata.previous_rejected_reports
    total_reviewed = accepted + rejected

    # Baseline for new / untested accounts
    if total_reviewed == 0:
        tier = ReporterReliabilityTier.NEW if metadata.account_age_days < 30 else ReporterReliabilityTier.UNTESTED
        score = 0.50
        if metadata.is_trusted:
            score = 0.70
            tier = ReporterReliabilityTier.ESTABLISHED
        return ReporterMetadata(
            reporter_id=metadata.reporter_id,
            account_age_days=metadata.account_age_days,
            previous_accepted_reports=accepted,
            previous_rejected_reports=rejected,
            is_trusted=metadata.is_trusted,
            is_restricted=False,
            calculated_reliability_score=score,
            assessed_tier=tier,
        )

    # Calculate historical acceptance ratio
    acceptance_ratio = accepted / total_reviewed

    # Penalize accounts with predominantly rejected reports
    if total_reviewed >= 3 and acceptance_ratio < 0.25:
        score = max(0.15, acceptance_ratio * 0.8)
        tier = ReporterReliabilityTier.UNTESTED
    elif total_reviewed >= 10 and acceptance_ratio >= 0.85:
        # Established high-reputation reporter
        score = min(0.95, 0.70 + (acceptance_ratio * 0.25))
        tier = ReporterReliabilityTier.HIGHLY_RELIABLE
    elif total_reviewed >= 3 and acceptance_ratio >= 0.60:
        score = 0.50 + (acceptance_ratio * 0.25)
        tier = ReporterReliabilityTier.ESTABLISHED
    else:
        score = 0.35 + (acceptance_ratio * 0.20)
        tier = ReporterReliabilityTier.UNTESTED

    if metadata.is_trusted:
        score = min(1.0, score + 0.15)
        if tier != ReporterReliabilityTier.HIGHLY_RELIABLE:
            tier = ReporterReliabilityTier.ESTABLISHED

    return ReporterMetadata(
        reporter_id=metadata.reporter_id,
        account_age_days=metadata.account_age_days,
        previous_accepted_reports=accepted,
        previous_rejected_reports=rejected,
        is_trusted=metadata.is_trusted,
        is_restricted=False,
        calculated_reliability_score=round(score, 4),
        assessed_tier=tier,
    )

