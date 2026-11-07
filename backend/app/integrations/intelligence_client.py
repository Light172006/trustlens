"""Integration client and typed interface for the TrustLens AI Intelligence Engine."""

import logging
from typing import Any

from shared.contracts.ai_contracts import (
    AIAssessment,
    AssessmentFinding,
    FindingCategory,
    FindingSeverity,
    ScanEvidence,
    Verdict,
)

logger = logging.getLogger("trustlens.integrations.intelligence")


class IntelligenceClient:
    """Client for invoking the TrustLens AI Intelligence Engine.

    Mediates between normalized backend scanner observations and the AI scoring engine.
    Uses the real `trustlens_intelligence` package if installed, falling back to a
    strictly deterministic test double that adheres to the PRD scoring rules and contracts.
    """

    def __init__(self) -> None:
        self._engine_available = False
        try:
            import importlib.util

            if importlib.util.find_spec("trustlens_intelligence") is not None:
                self._engine_available = True
                logger.info("Real trustlens_intelligence engine detected and linked.")
            else:
                logger.info(
                    "trustlens_intelligence package not installed; using certified test double."
                )
        except Exception:
            logger.info(
                "trustlens_intelligence package not installed; using certified test double."
            )

    def analyze(
        self,
        evidence: ScanEvidence,
        query_providers: bool = False,
        is_scan_failed: bool = False,
    ) -> AIAssessment:
        """Analyze normalized website scan evidence and return an explainable assessment."""
        if self._engine_available:
            try:
                from trustlens_intelligence.engine import analyze_website  # type: ignore

                raw_assessment = analyze_website(
                    evidence=evidence,
                    query_providers=query_providers,
                    is_scan_failed=is_scan_failed,
                )
                return self._validate_and_normalize_output(raw_assessment)
            except Exception as exc:
                logger.exception(f"Error calling trustlens_intelligence: {exc}")
                # Do not invent arbitrary SAFE verdict if external engine fails
                return self._create_inconclusive_fallback(
                    evidence=evidence,
                    error_message=f"AI Intelligence Engine error: {type(exc).__name__}",
                )

        # Execute test double conforming to PRD deterministic rules
        return self._evaluate_test_double(evidence=evidence, is_scan_failed=is_scan_failed)

    def _validate_and_normalize_output(self, assessment: Any) -> AIAssessment:
        """Ensure external intelligence output strictly conforms to Pydantic contract."""
        if isinstance(assessment, AIAssessment):
            return assessment

        if hasattr(assessment, "model_dump"):
            data = assessment.model_dump(mode="json")
        elif isinstance(assessment, dict):
            data = assessment
        else:
            data = vars(assessment)

        # Validate score bounds
        risk_score = data.get("risk_score")
        if risk_score is not None:
            if not (0 <= risk_score <= 100):
                raise ValueError(f"Risk score {risk_score} out of bounds (0-100)")

        # Validate confidence
        confidence = data.get("confidence", 0.0)
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Confidence {confidence} out of bounds (0.0-1.0)")

        return AIAssessment.model_validate(data)

    def _evaluate_test_double(self, evidence: ScanEvidence, is_scan_failed: bool) -> AIAssessment:
        """Deterministic contract-compliant test double implementing PRD scoring rules."""
        if is_scan_failed:
            return AIAssessment(
                verdict=Verdict.INCONCLUSIVE,
                risk_score=0,
                confidence=0.0,
                scoring_version="trustlens-1.0",
                findings=[
                    AssessmentFinding(
                        code="SCAN_EXECUTION_FAILED",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.WEB_SECURITY,
                        title="Scan execution incomplete",
                        description="The scan worker encountered an unrecoverable internal processing error.",
                        remediation="Retry the scan once service health is verified.",
                        source="trustlens_worker_internal",
                    )
                ],
                summary="Scan could not be completed due to an internal worker failure.",
            )

        findings: list[AssessmentFinding] = []
        points = 0

        # Rule 1: Decisive Threat Match (OpenPhish or URLhaus online)
        ti = evidence.threat_intelligence
        if ti.phishing_match or (
            ti.details.get("urlhaus_match") and ti.details.get("url_status") == "online"
        ):
            findings.append(
                AssessmentFinding(
                    code="DECISIVE_THREAT_INDICATOR_MATCH",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.THREAT_INTEL,
                    title="Known threat indicator match",
                    description="The canonical URL was identified in an authoritative active phishing or malware feed.",
                    remediation="Do not visit, download files from, or submit credentials to this website.",
                    source="threat_intelligence_feed",
                )
            )
            return AIAssessment(
                verdict=Verdict.MALICIOUS,
                risk_score=100,
                confidence=0.98,
                scoring_version="trustlens-1.0",
                findings=findings,
                summary="Malicious website detected via active threat intelligence match.",
            )

        # Rule 2: Decisive Community Match (2+ distinct confirmed reports)
        ci = evidence.community_intelligence
        if ci.confirmed_report_count >= 2:
            findings.append(
                AssessmentFinding(
                    code="COMMUNITY_CONFIRMED_INDICATOR",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingCategory.COMMUNITY,
                    title="Community confirmed threat reports",
                    description="Multiple independent, moderator-confirmed community threat reports exist for this URL.",
                    remediation="Avoid interacting with this domain.",
                    source="trustlens_community_curated",
                )
            )
            return AIAssessment(
                verdict=Verdict.MALICIOUS,
                risk_score=90,
                confidence=0.92,
                scoring_version="trustlens-1.0",
                findings=findings,
                summary="Malicious website confirmed by curated community threat intelligence.",
            )

        # Rule 3: TLS and Certificate Findings
        tls = evidence.tls
        if evidence.url.startswith("https://"):
            if not tls.valid or not tls.chain_valid:
                points += 25
                findings.append(
                    AssessmentFinding(
                        code="CERT_CHAIN_INVALID",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CERTIFICATE,
                        title="TLS certificate chain validation failed",
                        description="The TLS certificate presented by the server could not be verified by trusted root authorities.",
                        remediation="Ensure a valid, trusted certificate is installed.",
                        source="trustlens_tls_analyzer",
                    )
                )
            if not tls.hostname_match:
                points += 25
                findings.append(
                    AssessmentFinding(
                        code="CERT_HOSTNAME_MISMATCH",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CERTIFICATE,
                        title="Certificate hostname mismatch",
                        description="The certificate subject or SAN does not match the scanned hostname.",
                        remediation="Configure certificate Subject Alternative Names to match the domain.",
                        source="trustlens_tls_analyzer",
                    )
                )
            if tls.days_until_expiry is not None and tls.days_until_expiry < 0:
                points += 20
                findings.append(
                    AssessmentFinding(
                        code="CERT_EXPIRED",
                        severity=FindingSeverity.HIGH,
                        category=FindingCategory.CERTIFICATE,
                        title="TLS certificate has expired",
                        description="The server leaf certificate is past its validity expiry date.",
                        remediation="Renew the SSL/TLS certificate immediately.",
                        source="trustlens_tls_analyzer",
                    )
                )

        # Rule 4: Security Headers
        http = evidence.http
        sec_headers = http.security_headers
        if evidence.url.startswith("https://") and "strict-transport-security" not in sec_headers:
            points += 5
            findings.append(
                AssessmentFinding(
                    code="HSTS_MISSING",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.WEB_SECURITY,
                    title="HSTS not configured",
                    description="Strict-Transport-Security header was not detected.",
                    remediation="Add Strict-Transport-Security header.",
                    source="trustlens_header_analyzer",
                )
            )
        if "content-security-policy" not in sec_headers:
            points += 4
            findings.append(
                AssessmentFinding(
                    code="CSP_MISSING",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.WEB_SECURITY,
                    title="Content Security Policy missing",
                    description="Content-Security-Policy header was not detected.",
                    remediation="Configure a Content Security Policy.",
                    source="trustlens_header_analyzer",
                )
            )

        # Rule 5: Coverage Check for Sensitive / Stale Providers
        # If scan is sensitive or provider was unavailable, cannot return SAFE!
        if (
            evidence.is_sensitive
            or ti.openphish_status in ("unavailable", "stale_cache")
            or ti.urlhaus_status in ("unavailable", "skipped_sensitive_url")
        ):
            findings.append(
                AssessmentFinding(
                    code="COVERAGE_INSUFFICIENT",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.THREAT_INTEL,
                    title="Incomplete threat feed coverage",
                    description="One or more external threat lookups were skipped due to URL sensitivity or provider unavailability.",
                    remediation="Result is classified as Inconclusive to prevent false confidence.",
                    source="trustlens_coverage_checker",
                )
            )
            capped_points = min(points, 100)
            return AIAssessment(
                verdict=Verdict.INCONCLUSIVE,
                risk_score=capped_points,
                confidence=0.70,
                scoring_version="trustlens-1.0",
                findings=findings,
                summary="Assessment is inconclusive due to incomplete provider coverage.",
            )

        # Rule 6: Final Verdict Mapping
        capped_points = min(points, 100)
        if capped_points >= 25:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.85
            summary = "Suspicious technical configuration or certificate warnings detected."
        else:
            verdict = Verdict.SAFE
            confidence = 0.94
            summary = "No material security risks detected during passive technical checks."

        return AIAssessment(
            verdict=verdict,
            risk_score=capped_points,
            confidence=confidence,
            scoring_version="trustlens-1.0",
            findings=findings,
            summary=summary,
        )

    def _create_inconclusive_fallback(
        self, evidence: ScanEvidence, error_message: str
    ) -> AIAssessment:
        """Safe fallback assessment when AI engine fails."""
        return AIAssessment(
            verdict=Verdict.INCONCLUSIVE,
            risk_score=0,
            confidence=0.0,
            scoring_version="trustlens-1.0",
            findings=[
                AssessmentFinding(
                    code="INTELLIGENCE_ENGINE_UNAVAILABLE",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.THREAT_INTEL,
                    title="Intelligence Engine Unavailable",
                    description=error_message,
                    remediation="Review technical scan evidence manually.",
                    source="trustlens_integration_fallback",
                )
            ],
            summary="Assessment is inconclusive due to an external intelligence engine fault.",
        )


intelligence_client = IntelligenceClient()
