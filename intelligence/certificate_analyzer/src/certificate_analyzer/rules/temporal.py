"""Temporal and certificate lifecycle rules."""

from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class TemporalRules(CertificateRule):
    rule_id = "RULE_GROUP_TEMPORAL"
    name = "Temporal & Lifecycle Rules"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        findings: List[CertificateFinding] = []

        # 1. Expired
        if features.is_expired:
            findings.append(
                CertificateFinding(
                    code="RULE_EXPIRED",
                    title="Certificate Has Expired",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Certificate expired {abs(features.days_until_expiry)} days ago. Browsers will block connections with SEC_ERROR_EXPIRED_CERTIFICATE.",
                    evidence={"days_expired": abs(features.days_until_expiry)},
                    recommendation="Renew and install an active certificate immediately.",
                    score_deduction=DEDUCTIONS["EXPIRED"],
                )
            )

        # 2. Not Yet Valid
        if features.is_not_yet_valid:
            findings.append(
                CertificateFinding(
                    code="RULE_NOT_YET_VALID",
                    title="Certificate Is Not Yet Valid",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Certificate validity period begins in {abs(features.days_since_issuance)} days. Connections will fail.",
                    evidence={"days_until_valid": abs(features.days_since_issuance)},
                    recommendation="Verify server system time or use a certificate whose notBefore date has passed.",
                    score_deduction=DEDUCTIONS["NOT_YET_VALID"],
                )
            )

        # 3. Expiring Soon Warning
        if not features.is_expired and not features.is_not_yet_valid:
            if features.days_until_expiry <= 7:
                findings.append(
                    CertificateFinding(
                        code="RULE_EXPIRING_SOON_7_DAYS",
                        title="Certificate Expiring Within 7 Days",
                        severity=FindingSeverity.HIGH,
                        description=f"Certificate will expire in {features.days_until_expiry:.1f} days. Immediate renewal required.",
                        evidence={"days_until_expiry": features.days_until_expiry},
                        recommendation="Trigger ACME renewal or manually deploy replacement certificate.",
                        score_deduction=DEDUCTIONS["EXPIRING_SOON_7_DAYS"],
                    )
                )
            elif features.days_until_expiry <= 30:
                findings.append(
                    CertificateFinding(
                        code="RULE_EXPIRING_SOON_30_DAYS",
                        title="Certificate Expiring Within 30 Days",
                        severity=FindingSeverity.MEDIUM,
                        description=f"Certificate will expire in {features.days_until_expiry:.1f} days.",
                        evidence={"days_until_expiry": features.days_until_expiry},
                        recommendation="Schedule upcoming certificate replacement.",
                        score_deduction=DEDUCTIONS["EXPIRING_SOON_30_DAYS"],
                    )
                )

        # 4. Short-Lived Certificate Information
        if features.is_short_lived and not features.is_expired:
            findings.append(
                CertificateFinding(
                    code="RULE_SHORT_LIVED_LIFECYCLE",
                    title="Automated Short-Lived Lifecycle",
                    severity=FindingSeverity.INFO,
                    description=f"Certificate uses a short {features.validity_duration_days:.0f}-day validity window, aligning with PKI automation best practices.",
                    evidence={"validity_duration_days": features.validity_duration_days},
                    recommendation=None,
                    score_deduction=0,
                )
            )

        return findings

