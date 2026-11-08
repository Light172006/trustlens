"""
TrustLens Web Security Analyzer - Risk Aggregation & Synthesis Engine (Phase 7)
Synthesizes verified deterministic security findings, severity penalties, and ML calibrated probabilities.
Enforces that machine learning predictions can NEVER override verifiable technical weaknesses.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("risk_aggregator")

# Defensible Severity Penalty Mapping
SEVERITY_PENALTIES = {
    "CRITICAL": 35.0,
    "HIGH": 20.0,
    "MEDIUM": 10.0,
    "LOW": 3.0,
    "INFO": 0.0,
}

WARN_PENALTIES = {
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.0,
}


class RiskAggregator:
    """
    Synthesizes multi-source security telemetry, findings, and ML predictions into a unified posture report.
    """

    def aggregate_assessment(
        self,
        features: Dict[str, Any],
        findings: List[Dict[str, Any]],
        ml_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Combines deterministic findings, rubric scoring, and ML prediction into a comprehensive assessment.
        """
        # 1. Base Scoring & Finding Statistics
        base_score = 100.0
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0
        pass_count = 0

        affected_categories = set()
        prioritized_remediations = []

        for f in findings:
            status = f.get("status")
            sev = f.get("severity")
            cat = f.get("category")

            if status == "FAIL":
                affected_categories.add(cat)
                penalty = SEVERITY_PENALTIES.get(sev, 0.0)
                base_score -= penalty
                if sev == "CRITICAL":
                    crit_count += 1
                elif sev == "HIGH":
                    high_count += 1
                elif sev == "MEDIUM":
                    med_count += 1
                elif sev == "LOW":
                    low_count += 1

                rec = f.get("recommendation")
                if rec and rec != "None.":
                    prioritized_remediations.append({
                        "finding_id": f.get("finding_id"),
                        "severity": sev,
                        "category": cat,
                        "recommendation": rec,
                    })

            elif status == "WARN":
                affected_categories.add(cat)
                penalty = WARN_PENALTIES.get(sev, 0.0)
                base_score -= penalty
                if sev == "MEDIUM":
                    med_count += 1
                elif sev == "LOW":
                    low_count += 1

                rec = f.get("recommendation")
                if rec and rec != "None.":
                    prioritized_remediations.append({
                        "finding_id": f.get("finding_id"),
                        "severity": sev,
                        "category": cat,
                        "recommendation": rec,
                    })

            elif status == "PASS":
                pass_count += 1

        final_score = max(0.0, min(100.0, round(base_score, 1)))

        # 2. Deterministic Posture Assignment
        is_unreachable = not features.get("domain_resolved", False) or features.get("collection_status") in ("UNREACHABLE", "DNS_FAILURE")

        if is_unreachable:
            deterministic_posture = "INSUFFICIENT_EVIDENCE"
            final_score = 0.0
        elif crit_count > 0 or final_score < 50.0:
            deterministic_posture = "POOR"
        elif high_count > 0 or final_score < 80.0:
            deterministic_posture = "MODERATE"
        else:
            deterministic_posture = "GOOD"

        # 3. ML Posture Integration & Invariant Enforcement
        # Rule: ML prediction can NEVER override a confirmed technical weakness or unverified state
        ml_posture = ml_result.get("predicted_posture", "INSUFFICIENT_EVIDENCE")
        ml_confidence = ml_result.get("confidence", 0.0)
        ml_abstained = ml_result.get("abstained", True)

        final_posture = deterministic_posture
        consensus_status = "CONSENSUS"
        discrepancy_explanation = None

        if is_unreachable:
            final_posture = "INSUFFICIENT_EVIDENCE"
            consensus_status = "ABSTENTION_INSUFFICIENT_DATA"
            discrepancy_explanation = "Target endpoint failed resolution or connection; posture is indeterminable."
        elif crit_count > 0:
            # Irreversible critical weakness
            final_posture = "POOR"
            if ml_posture != "POOR" and not ml_abstained:
                consensus_status = "DETERMINISTIC_OVERRIDE"
                discrepancy_explanation = (
                    f"ML model predicted '{ml_posture}', but deterministic rule verified {crit_count} CRITICAL weakness(es). "
                    "Per safety invariants, confirmed technical vulnerabilities strictly enforce POOR posture."
                )
        elif deterministic_posture != ml_posture and not ml_abstained:
            consensus_status = "DISCREPANCY"
            discrepancy_explanation = (
                f"Deterministic evaluation assigned '{deterministic_posture}' (score {final_score}), "
                f"while ML model predicted '{ml_posture}' (confidence {ml_confidence:.2f}). "
                f"Deterministic assessment governs authoritative rating."
            )

        # Sort recommendations by severity order (CRITICAL -> HIGH -> MEDIUM -> LOW)
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        prioritized_remediations.sort(key=lambda x: sev_rank.get(x["severity"], 5))

        return {
            "final_posture": final_posture,
            "security_score": final_score,
            "deterministic_posture": deterministic_posture,
            "ml_prediction": ml_result,
            "consensus": {
                "status": consensus_status,
                "discrepancy_explanation": discrepancy_explanation,
            },
            "findings_summary": {
                "total_findings": len(findings),
                "critical_count": crit_count,
                "high_count": high_count,
                "medium_count": med_count,
                "low_count": low_count,
                "pass_count": pass_count,
                "affected_categories": sorted(list(affected_categories)),
            },
            "remediations": prioritized_remediations,
        }

