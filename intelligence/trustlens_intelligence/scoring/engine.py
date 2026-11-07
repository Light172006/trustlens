"""TrustLens Intelligence — Risk Scoring Engine Wrapper."""

from trustlens_intelligence.config.constants import CURRENT_SCORING_VERSION
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.calculator import RiskCalculator, ScoreCalculationResult
from trustlens_intelligence.scoring.weights import DEFAULT_WEIGHTS, ScoringWeights


class RiskScoringEngine:
    """Versioned risk scoring engine producing reproducible threat scores and verdicts."""

    version = CURRENT_SCORING_VERSION

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self.weights = weights or DEFAULT_WEIGHTS
        self.calculator = RiskCalculator(weights=self.weights)

    def score(
        self,
        evidence: ScanEvidence,
        findings: list[Finding],
        provider_checks: list[ProviderCheckResult],
        has_decisive_malicious: bool,
        is_scan_failed: bool = False,
    ) -> ScoreCalculationResult:
        """Calculate the risk score and verdict for the provided findings and coverage."""
        return self.calculator.calculate(
            evidence=evidence,
            findings=findings,
            provider_checks=provider_checks,
            has_decisive_malicious=has_decisive_malicious,
            is_scan_failed=is_scan_failed,
        )

