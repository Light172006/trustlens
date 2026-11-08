"""TrustLens Collaborative Threat Intelligence — Abuse & Manipulation Detection.

Identifies coordinated reporting, Sybil clusters, duplicate evidence reuse,
and reporting bursts designed to manipulate threat intelligence or harm legitimate hosts.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import difflib
from typing import List, Set

from collaborative_intelligence.config import AbuseDetectionConfig
from collaborative_intelligence.enums import AbuseSignalType
from collaborative_intelligence.evidence import compute_evidence_fingerprint
from collaborative_intelligence.models import (
    AbuseDetectionResult,
    CommunityReportInput,
)


class AbuseDetector:
    """Detects coordination, Sybil patterns, and manipulation signals across reports."""

    def __init__(self, config: AbuseDetectionConfig | None = None) -> None:
        self.config = config or AbuseDetectionConfig()

    def analyze_reports(
        self,
        reports: List[CommunityReportInput],
    ) -> AbuseDetectionResult:
        """Analyze a collection of community reports for abuse patterns.

        Args:
            reports: Collection of reports referencing an indicator or cluster.

        Returns:
            AbuseDetectionResult with detected signals, risk rating, and explanations.
        """
        if len(reports) <= 1:
            return AbuseDetectionResult(
                is_suspicious=False,
                manipulation_risk="LOW",
                signals=[],
                reasons=["Single report evaluated; insufficient volume for coordinated abuse patterns."],
            )

        signals: set[AbuseSignalType] = set()
        reasons: list[str] = []

        # 1. Check for Duplicate Evidence reuse across different reporter accounts
        fingerprint_to_reporters: dict[str, set[str]] = defaultdict(set)
        for rep in reports:
            for item in rep.evidence_items:
                fp = item.fingerprint or compute_evidence_fingerprint(item)
                fingerprint_to_reporters[fp].add(rep.reporter.reporter_id)

        shared_evidence_reporters = [
            (fp, reps) for fp, reps in fingerprint_to_reporters.items() if len(reps) > 1
        ]
        if shared_evidence_reporters:
            signals.add(AbuseSignalType.DUPLICATE_EVIDENCE)
            signals.add(AbuseSignalType.COORDINATED_SUBMISSION)
            reasons.append(
                f"Identical evidence fingerprint reused across {len(shared_evidence_reporters[0][1])} "
                "distinct reporter accounts. Indicates copied evidence or coordinated submission."
            )

        # 2. Check for Identical or near-identical text descriptions across accounts
        unique_reporters = {r.reporter.reporter_id for r in reports}
        if len(unique_reporters) > 1:
            descriptions = [(r.reporter.reporter_id, r.description.strip()) for r in reports if len(r.description.strip()) > 15]
            for i in range(len(descriptions)):
                for j in range(i + 1, len(descriptions)):
                    u1, d1 = descriptions[i]
                    u2, d2 = descriptions[j]
                    if u1 != u2:
                        ratio = difflib.SequenceMatcher(None, d1.lower(), d2.lower()).ratio()
                        if ratio >= self.config.identical_payload_similarity_threshold:
                            signals.add(AbuseSignalType.IDENTICAL_PAYLOAD)
                            reasons.append(
                                f"Near-identical report descriptions ({ratio:.0%} similarity) submitted by "
                                f"different accounts ('{u1}' and '{u2}'). Suggests scripted copy-paste campaign."
                            )
                            break
                if AbuseSignalType.IDENTICAL_PAYLOAD in signals:
                    break

        # 3. Check for Sudden Reporting Bursts
        timestamps = sorted([r.submitted_at for r in reports])
        burst_detected = False
        for i in range(len(timestamps)):
            window_count = 1
            start_t = timestamps[i]
            for j in range(i + 1, len(timestamps)):
                diff_sec = (timestamps[j] - start_t).total_seconds()
                if diff_sec <= self.config.burst_window_seconds:
                    window_count += 1
                else:
                    break
            if window_count >= self.config.burst_threshold_per_host:
                burst_detected = True
                signals.add(AbuseSignalType.BURST_REPORTING)
                reasons.append(
                    f"Reporting burst detected: {window_count} reports submitted within "
                    f"{self.config.burst_window_seconds} seconds."
                )
                break

        # 4. Check for Sybil Cluster (Multiple new/untested accounts acting together)
        new_account_reporters = [
            r.reporter.reporter_id
            for r in reports
            if r.reporter.account_age_days < 7
            and (r.reporter.previous_accepted_reports + r.reporter.previous_rejected_reports) == 0
        ]
        distinct_new_reporters = set(new_account_reporters)
        if len(distinct_new_reporters) >= self.config.min_reporters_for_sybil_check and (
            AbuseSignalType.DUPLICATE_EVIDENCE in signals
            or AbuseSignalType.IDENTICAL_PAYLOAD in signals
            or burst_detected
        ):
            signals.add(AbuseSignalType.SYBIL_CLUSTER)
            reasons.append(
                f"Sybil cluster signature: {len(distinct_new_reporters)} new accounts (<7 days old) "
                "submitting correlated or duplicated reports."
            )

        # 5. Check for Low-Reputation / Restricted Account Burst
        restricted_reporters = [r.reporter.reporter_id for r in reports if r.reporter.is_restricted]
        if len(restricted_reporters) > 0 and len(restricted_reporters) == len(reports):
            signals.add(AbuseSignalType.LOW_REPUTATION_BURST)
            reasons.append(
                "All reporting accounts in this cluster have restricted status."
            )

        # Calculate manipulation risk band
        is_suspicious = len(signals) > 0
        if AbuseSignalType.SYBIL_CLUSTER in signals or (
            AbuseSignalType.DUPLICATE_EVIDENCE in signals and AbuseSignalType.BURST_REPORTING in signals
        ):
            risk = "HIGH"
        elif len(signals) >= 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        if not reasons:
            reasons.append("No coordination, Sybil, or flood patterns detected.")

        return AbuseDetectionResult(
            is_suspicious=is_suspicious,
            manipulation_risk=risk,
            signals=sorted(list(signals), key=lambda s: s.value),
            reasons=reasons,
        )

