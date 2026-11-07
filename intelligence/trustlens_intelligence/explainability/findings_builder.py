"""TrustLens Intelligence — Explainable Findings Builder.

Ensures every finding includes concrete observed evidence, actionable remediation,
and complies with the TrustLens explainability invariant.
"""

from typing import Any
import uuid

from trustlens_intelligence.config.constants import FindingCategory, FindingSeverity, LayerCoverage, Verdict
from trustlens_intelligence.schemas.findings import Finding


def create_coverage_inconclusive_finding(
    coverage: dict[str, LayerCoverage],
    details: dict[str, Any] | None = None,
) -> Finding:
    """Generate an explicit finding when an assessment is INCONCLUSIVE due to incomplete coverage."""
    incomplete_layers = [k for k, v in coverage.items() if v in (LayerCoverage.UNAVAILABLE, LayerCoverage.PARTIAL)]
    layers_str = ", ".join(incomplete_layers) if incomplete_layers else "threat intelligence"

    return Finding(
        id=str(uuid.uuid4()),
        code="COVERAGE_INSUFFICIENT",
        category=FindingCategory.THREAT_INTEL,
        title="Threat intelligence coverage incomplete",
        description=(
            f"TrustLens could not verify safety because one or more required analysis layers ({layers_str}) "
            "did not produce fresh or complete evidence. Missing evidence cannot be treated as clean."
        ),
        severity=FindingSeverity.MEDIUM,
        points=0,
        evidence={"coverage": {k: v.value for k, v in coverage.items()}, "details": details or {}},
        remediation="Do not assume this website is safe. Wait for provider services to restore or verify via independent channels.",
        source="trustlens_coverage_auditor",
    )

