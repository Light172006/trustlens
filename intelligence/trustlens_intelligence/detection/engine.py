"""TrustLens Intelligence — Deterministic Threat Detection Engine."""

import logging
from typing import NamedTuple

from trustlens_intelligence.config.constants import FindingSeverity
from trustlens_intelligence.detection.registry import RuleRegistry
from trustlens_intelligence.schemas.evidence import ScanEvidence
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding

logger = logging.getLogger("trustlens.intelligence.detection.engine")

SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 5,
    FindingSeverity.HIGH: 4,
    FindingSeverity.MEDIUM: 3,
    FindingSeverity.LOW: 2,
    FindingSeverity.INFO: 1,
}


class DetectionResult(NamedTuple):
    """Result of running detection rules against evidence and features."""

    findings: list[Finding]
    has_decisive_malicious: bool
    decisive_rule_codes: list[str]


class DetectionEngine:
    """Evaluates evidence against configured deterministic detection rules."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or RuleRegistry()

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> DetectionResult:
        """Evaluate all active detection rules.

        Args:
            evidence: Normalized scan observations.
            features: Extracted features.

        Returns:
            DetectionResult with findings and decisive flags.
        """
        findings: list[Finding] = []
        has_decisive = False
        decisive_codes: list[str] = []

        seen_codes: set[str] = set()

        for rule in self.registry:
            try:
                finding = rule.evaluate(evidence, features)
                if finding:
                    if finding.code in seen_codes:
                        continue
                    seen_codes.add(finding.code)
                    findings.append(finding)

                    if rule.is_decisive:
                        has_decisive = True
                        decisive_codes.append(rule.code)
            except Exception as exc:
                logger.error("Error evaluating detection rule %s: %s", rule.code, exc, exc_info=True)

        # Sort findings by severity descending, then points descending
        findings.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 0),
                f.points,
            ),
            reverse=True,
        )

        return DetectionResult(
            findings=findings,
            has_decisive_malicious=has_decisive,
            decisive_rule_codes=decisive_codes,
        )

