"""Tests for TrustLens Explainability Engine and Finding Invariants."""

import pytest

from trustlens_intelligence.config.constants import FindingCategory, FindingSeverity, LayerCoverage, Verdict
from trustlens_intelligence.explainability.explainer import ExplainabilityEngine
from trustlens_intelligence.schemas.findings import Finding


def test_explainability_invariant_for_non_safe_verdicts():
    """100% of non-SAFE verdicts must contain at least one explanatory finding."""
    explainer = ExplainabilityEngine()
    coverage = {
        "threat_intel": LayerCoverage.UNAVAILABLE,
        "web_security": LayerCoverage.COMPLETE,
        "certificate": LayerCoverage.COMPLETE,
        "community": LayerCoverage.COMPLETE,
    }

    # An empty findings list with an INCONCLUSIVE verdict
    empty_findings: list[Finding] = []
    ensured_findings = explainer.ensure_explainability_invariants(
        verdict=Verdict.INCONCLUSIVE,
        findings=empty_findings,
        coverage=coverage,
    )

    assert len(ensured_findings) >= 1
    assert ensured_findings[0].code == "COVERAGE_INSUFFICIENT"
    assert "threat_intel" in str(ensured_findings[0].description)


def test_malicious_summary_references_decisive_finding():
    """Malicious verdict summary references actual triggering indicators."""
    explainer = ExplainabilityEngine()
    findings = [
        Finding(
            code="OPENPHISH_URL_MATCH",
            category=FindingCategory.THREAT_INTEL,
            title="Known phishing URL verified by OpenPhish",
            description="Matched in feed",
            severity=FindingSeverity.CRITICAL,
            points=100,
            remediation="Do not visit",
            source="openphish",
        )
    ]
    summary = explainer.build_summary(
        verdict=Verdict.MALICIOUS,
        risk_score=100,
        findings=findings,
        coverage={"threat_intel": LayerCoverage.COMPLETE},
    )

    assert "Do not visit" in summary
    assert "OpenPhish" in summary


def test_safe_summary_disclaimer():
    """SAFE verdict summary includes bounded assessment disclaimer."""
    explainer = ExplainabilityEngine()
    summary = explainer.build_summary(
        verdict=Verdict.SAFE,
        risk_score=0,
        findings=[],
        coverage={"threat_intel": LayerCoverage.COMPLETE},
    )

    assert "No material risk was found" in summary
    assert "Continue to verify the site's identity" in summary

