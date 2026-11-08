"""Rule execution engine for Certificate Analyzer."""

from typing import Any, Dict, List, Optional
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.rules.cryptographic import CryptographicRules
from certificate_analyzer.rules.hierarchy import HierarchyRules
from certificate_analyzer.rules.identity import IdentityRules
from certificate_analyzer.rules.policy import PolicyRules
from certificate_analyzer.rules.revocation_verifier import RevocationRules
from certificate_analyzer.rules.temporal import TemporalRules
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CertificateRuleEngine:
    """Executes registered certificate analysis rules and returns prioritized findings."""

    def __init__(self, custom_rules: Optional[List[CertificateRule]] = None):
        self.rules: List[CertificateRule] = custom_rules or [
            CryptographicRules(),
            TemporalRules(),
            HierarchyRules(),
            IdentityRules(),
            PolicyRules(),
        ]

    def evaluate_all(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
        revocation_record: Optional[Dict[str, Any]] = None,
        reference_time: Optional[Any] = None,
    ) -> List[CertificateFinding]:
        """Runs all rules and returns findings sorted by severity (CRITICAL first)."""
        all_findings: List[CertificateFinding] = []
        for rule in self.rules:
            findings = rule.evaluate(features, cert_record, chain_record, context)
            all_findings.extend(findings)

        # Evaluate revocation rules if applicable
        if reference_time is not None:
            rev_findings = RevocationRules.evaluate_revocation_observation(revocation_record, reference_time)
            all_findings.extend(rev_findings)

        # Sort order: CRITICAL, HIGH, MEDIUM, LOW, INFO
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))
        return all_findings
