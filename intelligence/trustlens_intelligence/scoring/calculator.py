"""TrustLens Intelligence — Deterministic Risk Score Calculator.

Implements scoring logic, point aggregation, verdict threshold mapping,
coverage assessment, and confidence calibration per PRD FR-09.
"""

from typing import Any, NamedTuple

from trustlens_intelligence.config.constants import (
    LayerCoverage,
    ProviderName,
    ProviderResultStatus,
    Verdict,
)
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.weights import DEFAULT_WEIGHTS, ScoringWeights


class ScoreCalculationResult(NamedTuple):
    """Output of risk score and verdict computation."""

    score: int | None
    verdict: Verdict
    confidence: float
    coverage: dict[str, LayerCoverage]
    checks_completed: int
    decisive_triggered: bool
    details: dict[str, Any]


class RiskCalculator:
    """Deterministic score and verdict calculator."""

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS

    def evaluate_layer_coverage(
        self,
        evidence: ScanEvidence,
        provider_checks: list[ProviderCheckResult],
    ) -> dict[str, LayerCoverage]:
        """Compute the coverage status across the 4 analysis layers."""
        coverage: dict[str, LayerCoverage] = {}

        # 1. Threat Intel Coverage
        if not provider_checks:
            coverage["threat_intel"] = LayerCoverage.UNAVAILABLE
        else:
            status_map = {p.provider: p.result_status for p in provider_checks}
            openphish_st = status_map.get(ProviderName.OPENPHISH.value)
            urlhaus_st = status_map.get(ProviderName.URLHAUS.value)

            clean_set = {ProviderResultStatus.MATCH, ProviderResultStatus.NO_MATCH}
            if openphish_st in clean_set and urlhaus_st in clean_set:
                coverage["threat_intel"] = LayerCoverage.COMPLETE
            elif any(p.matched for p in provider_checks):
                coverage["threat_intel"] = LayerCoverage.COMPLETE
            else:
                coverage["threat_intel"] = LayerCoverage.PARTIAL

        # 2. Web Security Coverage
        if evidence.http and evidence.http.status_code is not None:
            coverage["web_security"] = LayerCoverage.COMPLETE
        elif evidence.http:
            coverage["web_security"] = LayerCoverage.PARTIAL
        else:
            coverage["web_security"] = LayerCoverage.UNAVAILABLE

        # 3. Certificate Coverage
        scheme = (evidence.scheme or "").lower()
        if scheme == "https":
            if evidence.tls and (evidence.tls.chain_valid is not None or evidence.tls.valid is not None):
                coverage["certificate"] = LayerCoverage.COMPLETE
            elif evidence.tls:
                coverage["certificate"] = LayerCoverage.PARTIAL
            else:
                coverage["certificate"] = LayerCoverage.UNAVAILABLE
        else:
            # Plain HTTP does not have a leaf certificate
            coverage["certificate"] = LayerCoverage.NOT_APPLICABLE

        # 4. Community Coverage
        if evidence.community_intelligence is not None:
            coverage["community"] = LayerCoverage.COMPLETE
        else:
            coverage["community"] = LayerCoverage.COMPLETE  # Defaulting community to complete if no reports

        return coverage

    def calculate_confidence(
        self,
        coverage: dict[str, LayerCoverage],
        has_decisive: bool,
    ) -> float:
        """Estimate confidence (0.0 to 1.0) based on coverage and decisive signals."""
        if has_decisive:
            return 0.95

        layer_weights: dict[str, float] = {
            "threat_intel": 0.35,
            "web_security": 0.25,
            "certificate": 0.25,
            "community": 0.15,
        }

        total_weight = 0.0
        earned_weight = 0.0

        for layer, weight in layer_weights.items():
            status = coverage.get(layer, LayerCoverage.UNAVAILABLE)
            if status == LayerCoverage.NOT_APPLICABLE:
                # Omit layer and redistribute weight
                continue

            total_weight += weight
            if status == LayerCoverage.COMPLETE:
                earned_weight += weight
            elif status == LayerCoverage.PARTIAL:
                earned_weight += weight * 0.5

        if total_weight <= 0.0:
            return 0.1

        base_conf = earned_weight / total_weight
        return round(max(0.1, min(1.0, base_conf)), 2)

    def calculate(
        self,
        evidence: ScanEvidence,
        findings: list[Finding],
        provider_checks: list[ProviderCheckResult],
        has_decisive_malicious: bool,
        is_scan_failed: bool = False,
    ) -> ScoreCalculationResult:
        """Compute final deterministic risk score and verdict."""
        coverage = self.evaluate_layer_coverage(evidence, provider_checks)
        checks_completed = sum(1 for c in coverage.values() if c in (LayerCoverage.COMPLETE, LayerCoverage.NOT_APPLICABLE))

        # Handle failed scan where assessment is impossible
        if is_scan_failed:
            return ScoreCalculationResult(
                score=None,
                verdict=Verdict.INCONCLUSIVE,
                confidence=0.0,
                coverage=coverage,
                checks_completed=checks_completed,
                decisive_triggered=False,
                details={"reason": "Internal scan failure without reliable evidence"},
            )

        # 1. Decisive Malicious Rules check
        if has_decisive_malicious:
            decisive_findings = [f for f in findings if f.points >= 90 and f.severity == "critical"]
            max_pts = max((f.points for f in decisive_findings), default=100)
            score = min(self.weights.max_score, max_pts)
            confidence = self.calculate_confidence(coverage, has_decisive=True)
            return ScoreCalculationResult(
                score=score,
                verdict=Verdict.MALICIOUS,
                confidence=confidence,
                coverage=coverage,
                checks_completed=checks_completed,
                decisive_triggered=True,
                details={"decisive_rule": [f.code for f in decisive_findings]},
            )

        # 2. Additive Scoring with finding code deduplication
        additive_points = 0
        point_breakdown: dict[str, int] = {}
        seen_codes: set[str] = set()

        for finding in findings:
            if finding.code in seen_codes:
                continue
            seen_codes.add(finding.code)
            pts = finding.points
            additive_points += pts
            point_breakdown[finding.code] = pts

        raw_score = additive_points
        capped_score = min(self.weights.max_score, raw_score)

        # 3. Verdict Threshold Determination
        # PRD FR-09:
        # Score 25-74: SUSPICIOUS
        # Score 75-100: SUSPICIOUS (high score alone cannot prove malicious intent without decisive threat match)
        # Score 0-24 with complete coverage: SAFE
        # Score 0-24 without complete coverage: INCONCLUSIVE
        confidence = self.calculate_confidence(coverage, has_decisive=False)

        if capped_score >= self.weights.suspicious_min:
            verdict = Verdict.SUSPICIOUS
        else:
            # Score is 0-24
            # Required coverage check for SAFE:
            threat_complete = coverage.get("threat_intel") == LayerCoverage.COMPLETE
            web_complete = coverage.get("web_security") == LayerCoverage.COMPLETE
            cert_status = coverage.get("certificate")
            cert_acceptable = cert_status in (LayerCoverage.COMPLETE, LayerCoverage.NOT_APPLICABLE)

            if threat_complete and web_complete and cert_acceptable:
                verdict = Verdict.SAFE
            else:
                # Insufficient coverage prevents a clean SAFE verdict
                verdict = Verdict.INCONCLUSIVE

        return ScoreCalculationResult(
            score=capped_score,
            verdict=verdict,
            confidence=confidence,
            coverage=coverage,
            checks_completed=checks_completed,
            decisive_triggered=False,
            details={"raw_score": raw_score, "capped_score": capped_score, "point_breakdown": point_breakdown},
        )

