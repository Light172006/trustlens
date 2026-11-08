"""TrustLens Collaborative Threat Intelligence — Evidence Evaluation Layer.

Evaluates supporting and contradicting evidence for reports and indicators.
Enforces cryptographic evidence fingerprinting, diversity calculation,
and provenance verification. Never executes network requests.
"""

from __future__ import annotations

import hashlib
from typing import List, Set

from collaborative_intelligence.config import EvidenceEvaluationConfig
from collaborative_intelligence.enums import EvidenceStance, EvidenceType
from collaborative_intelligence.models import (
    EvidenceEvaluationResult,
    EvidenceItem,
)


def compute_evidence_fingerprint(item: EvidenceItem) -> str:
    """Compute a deterministic cryptographic fingerprint of an evidence item.

    Used to detect duplicate evidence reuse across reports or accounts.
    """
    clean_desc = " ".join(item.description.strip().lower().split())
    clean_src = item.source.strip().lower()
    raw = f"{item.evidence_type.value}:{item.stance.value}:{clean_src}:{clean_desc}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EvidenceEvaluator:
    """Evaluates the quality, credibility, stance, and diversity of evidence items."""

    def __init__(self, config: EvidenceEvaluationConfig | None = None) -> None:
        self.config = config or EvidenceEvaluationConfig()

    def evaluate(self, items: List[EvidenceItem]) -> EvidenceEvaluationResult:
        """Evaluate a collection of evidence items.

        Args:
            items: List of evidence items attached to a report or indicator.

        Returns:
            EvidenceEvaluationResult detailing scores, stance counts, and provenance.
        """
        if not items:
            return EvidenceEvaluationResult(
                evidence_quality_score=0.0,
                evidence_diversity_score=0.0,
                supporting_count=0,
                contradicting_count=0,
                inconclusive_count=0,
                unverified_count=0,
                distinct_fingerprints=[],
                evaluated_items=[],
                explanations=["No evidence items provided with this submission."],
            )

        evaluated_items: list[EvidenceItem] = []
        fingerprints_seen: set[str] = set()
        unique_fingerprints: list[str] = []
        supporting_types: set[EvidenceType] = set()

        supporting_count = 0
        contradicting_count = 0
        inconclusive_count = 0
        unverified_count = 0

        weighted_supporting_sum = 0.0
        total_supporting_weight = 0.0
        contradicting_impact = 0.0
        explanations: list[str] = []

        for item in items:
            # 1. Compute fingerprint if missing
            fp = item.fingerprint or compute_evidence_fingerprint(item)
            if fp not in fingerprints_seen:
                fingerprints_seen.add(fp)
                unique_fingerprints.append(fp)
                is_duplicate_evidence = False
            else:
                is_duplicate_evidence = True

            # Create updated item with guaranteed fingerprint
            evaluated_item = EvidenceItem(
                evidence_id=item.evidence_id,
                evidence_type=item.evidence_type,
                stance=item.stance,
                source=item.source,
                description=item.description,
                observed_at=item.observed_at,
                reliability_score=item.reliability_score,
                fingerprint=fp,
                is_verified=item.is_verified,
                metadata={**item.metadata, "is_duplicate_within_batch": is_duplicate_evidence},
            )
            evaluated_items.append(evaluated_item)

            if not item.is_verified:
                unverified_count += 1

            # 2. Tally stances
            if item.stance == EvidenceStance.SUPPORTS:
                supporting_count += 1
                if not is_duplicate_evidence:
                    supporting_types.add(item.evidence_type)
            elif item.stance == EvidenceStance.CONTRADICTS:
                contradicting_count += 1
            else:
                inconclusive_count += 1

            # 3. Calculate item quality contribution (duplicate items get zero weight)
            if is_duplicate_evidence:
                continue

            base_type_weight = self.config.type_weights.get(item.evidence_type.value, 0.3)

            # Apply verification penalty
            verification_factor = 1.0 if item.is_verified else self.config.unverified_penalty

            # Description specificity heuristic: brief/generic descriptions penalize score
            desc_len = len(item.description.strip())
            desc_factor = 0.5 if desc_len < 20 else (1.0 if desc_len >= 50 else 0.8)

            item_score = base_type_weight * verification_factor * desc_factor

            # Blend with explicit reliability score if present
            if item.reliability_score is not None:
                item_score = (item_score + item.reliability_score) / 2.0

            if item.stance == EvidenceStance.SUPPORTS:
                weighted_supporting_sum += item_score
                total_supporting_weight += 1.0
            elif item.stance == EvidenceStance.CONTRADICTS:
                # Contradicting evidence measures the strength of counter-evidence
                contradicting_impact += item_score * self.config.contradiction_weight_multiplier

        # Base supporting quality score
        if total_supporting_weight > 0:
            raw_quality = weighted_supporting_sum / total_supporting_weight
        else:
            raw_quality = 0.0

        # Contradiction penalty: if contradiction exists, reduce net supporting quality
        if contradicting_count > 0:
            penalty = 0.30 * contradicting_count + (contradicting_impact * 0.20)
            net_quality = max(0.0, raw_quality - penalty)
            explanations.append(
                f"Contradictory evidence detected ({contradicting_count} item(s)). "
                f"Evidence quality reduced by {penalty:.2f}."
            )
        else:
            net_quality = raw_quality

        net_quality = min(1.0, max(0.0, net_quality))

        # Diversity score: based on number of distinct supporting evidence types
        # 1 type -> 0.33, 2 types -> 0.67, 3+ types -> 1.0
        diversity_score = min(1.0, len(supporting_types) / 3.0)

        if unverified_count > 0:
            explanations.append(
                f"{unverified_count} evidence item(s) are unverified community submissions. "
                "Unverified evidence penalty applied."
            )

        if len(unique_fingerprints) < len(items):
            duplicate_evidence_count = len(items) - len(unique_fingerprints)
            explanations.append(
                f"Duplicate evidence detected ({duplicate_evidence_count} redundant item(s)). "
                "Redundant items discarded from diversity and corroboration calculations."
            )

        return EvidenceEvaluationResult(
            evidence_quality_score=round(net_quality, 4),
            evidence_diversity_score=round(diversity_score, 4),
            supporting_count=supporting_count,
            contradicting_count=contradicting_count,
            inconclusive_count=inconclusive_count,
            unverified_count=unverified_count,
            distinct_fingerprints=unique_fingerprints,
            evaluated_items=evaluated_items,
            explanations=explanations,
        )
