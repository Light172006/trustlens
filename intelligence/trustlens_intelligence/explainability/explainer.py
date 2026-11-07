"""TrustLens Intelligence — Explainability and Narrative Summary Engine.

Translates deterministic detection findings and coverage metrics into
human-readable executive summaries suitable for direct consumption by frontend and backend.
"""

from trustlens_intelligence.config.constants import LayerCoverage, Verdict
from trustlens_intelligence.explainability.findings_builder import create_coverage_inconclusive_finding
from trustlens_intelligence.schemas.findings import Finding

VERDICT_SUMMARIES: dict[Verdict, str] = {
    Verdict.SAFE: (
        "No material risk was found by the checks performed. "
        "Continue to verify the site's identity before sharing sensitive information."
    ),
    Verdict.SUSPICIOUS: (
        "Use caution; multiple security risks or anomalous configurations were detected. "
        "Avoid entering credentials or sensitive data until independently verified."
    ),
    Verdict.MALICIOUS: (
        "Do not visit, download files, execute payments, or enter credentials on this URL. "
        "Active threat intelligence or verified community reports confirmed this site as malicious."
    ),
    Verdict.INCONCLUSIVE: (
        "TrustLens could not collect sufficient reliable evidence to render a conclusive verdict. "
        "Do not interpret this result as safe."
    ),
}


class ExplainabilityEngine:
    """Generates structured explanations and enforces explainability invariants."""

    def build_summary(
        self,
        verdict: Verdict,
        risk_score: int | None,
        findings: list[Finding],
        coverage: dict[str, LayerCoverage],
    ) -> str:
        """Construct an executive narrative summary for the assessment."""
        base_summary = VERDICT_SUMMARIES.get(verdict, VERDICT_SUMMARIES[Verdict.INCONCLUSIVE])

        if verdict == Verdict.MALICIOUS:
            decisive = [f for f in findings if f.points >= 90 or f.severity == "critical"]
            if decisive:
                reasons = ", ".join(f.title for f in decisive[:2])
                return f"{base_summary} Key reason(s): {reasons}."
            return base_summary

        if verdict == Verdict.SUSPICIOUS:
            high_findings = [f for f in findings if f.points >= 15]
            if high_findings:
                reasons = "; ".join(f.title for f in high_findings[:2])
                return f"{base_summary} Notable findings: {reasons} (Risk Score: {risk_score}/100)."
            return f"{base_summary} (Risk Score: {risk_score}/100)."

        if verdict == Verdict.INCONCLUSIVE:
            incomplete = [k for k, v in coverage.items() if v in (LayerCoverage.UNAVAILABLE, LayerCoverage.PARTIAL)]
            if incomplete:
                return (
                    f"{base_summary} Incomplete or unavailable evidence layers: {', '.join(incomplete)}."
                )
            return base_summary

        # SAFE
        return base_summary

    def ensure_explainability_invariants(
        self,
        verdict: Verdict,
        findings: list[Finding],
        coverage: dict[str, LayerCoverage],
    ) -> list[Finding]:
        """Ensure that every non-SAFE verdict contains at least one explanatory finding."""
        if verdict != Verdict.SAFE and len(findings) == 0:
            fallback = create_coverage_inconclusive_finding(coverage)
            return [fallback]
        return findings

