"""Domain and identity authentication rules conforming to RFC 9525."""

from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class IdentityRules(CertificateRule):
    rule_id = "RULE_GROUP_IDENTITY"
    name = "Domain & Service Identity Rules (RFC 9525)"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        findings: List[CertificateFinding] = []

        dom_id = cert_record.get("domain_identity", {})
        dns_sans = dom_id.get("dns_san_entries", [])
        ip_sans = dom_id.get("ip_san_entries", [])

        # 1. Missing SAN Extension (RFC 9525 & RFC 5280 requirement for TLS endpoints)
        if cert_record.get("certificate_type") == "LEAF" and not features.has_san:
            findings.append(
                CertificateFinding(
                    code="RULE_MISSING_SAN_EXTENSION",
                    title="Missing Subject Alternative Name Extension",
                    severity=FindingSeverity.MEDIUM,
                    description="Certificate lacks the Subject Alternative Name (SAN) extension. Under RFC 9525, legacy Common Name matching is prohibited.",
                    evidence={"subject_dn": cert_record.get("subject_dn")},
                    recommendation="Reissue certificate with dNSName or iPAddress SAN entries for all service endpoints.",
                    score_deduction=DEDUCTIONS["MISSING_SAN_EXTENSION"],
                )
            )

        # 2. Hostname / IP Verification per RFC 9525
        if context and context.target_hostname:
            matched, status, matched_pattern = RFC9525IdentityVerifier.verify(
                reference_identity=context.target_hostname,
                dns_sans=dns_sans,
                ip_sans=ip_sans,
            )

            if matched:
                findings.append(
                    CertificateFinding(
                        code="RULE_HOSTNAME_MATCHED",
                        title=f"Service Identity Authenticated for '{context.target_hostname}'",
                        severity=FindingSeverity.INFO,
                        description=f"Target '{context.target_hostname}' successfully verified against certificate SAN pattern '{matched_pattern}' complying with RFC 9525.",
                        evidence={
                            "reference_identity": context.target_hostname,
                            "matched_pattern": matched_pattern,
                            "verification_status": status,
                        },
                        recommendation=None,
                        score_deduction=0,
                    )
                )
            else:
                findings.append(
                    CertificateFinding(
                        code="RULE_HOSTNAME_MISMATCH",
                        title=f"Hostname Mismatch for '{context.target_hostname}'",
                        severity=FindingSeverity.CRITICAL,
                        description=f"Presented certificate does not match requested service identity '{context.target_hostname}' under RFC 9525 rules.",
                        evidence={
                            "reference_identity": context.target_hostname,
                            "dns_sans": dns_sans,
                            "ip_sans": ip_sans,
                            "verification_status": status,
                        },
                        recommendation=f"Add '{context.target_hostname}' to certificate SANs or deploy a certificate covering this domain/IP.",
                        score_deduction=DEDUCTIONS["HOSTNAME_MISMATCH"],
                    )
                )
        else:
            # Explicitly record when hostname verification is not checked
            findings.append(
                CertificateFinding(
                    code="RULE_HOSTNAME_NOT_CHECKED",
                    title="Service Identity Not Evaluated",
                    severity=FindingSeverity.INFO,
                    description="No target hostname was supplied by the caller. Service identity authentication was skipped per RFC 9525.",
                    evidence=None,
                    recommendation="Provide target_hostname context to authenticate certificate against the TLS endpoint domain.",
                    score_deduction=0,
                )
            )

        return findings
