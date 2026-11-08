"""Chain hierarchy and trust store rules."""

from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class HierarchyRules(CertificateRule):
    rule_id = "RULE_GROUP_HIERARCHY"
    name = "Trust Hierarchy & Chain Rules"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        findings: List[CertificateFinding] = []

        # 1. Self-Signed Subscriber Leaf Certificate
        if features.is_self_signed and not features.is_ca:
            findings.append(
                CertificateFinding(
                    code="RULE_SELF_SIGNED_LEAF",
                    title="Self-Signed Leaf Certificate",
                    severity=FindingSeverity.HIGH,
                    description="Certificate is self-signed and not issued by a recognized Certificate Authority. Standard TLS clients will reject the connection.",
                    evidence={"subject_dn": cert_record.get("subject_dn")},
                    recommendation="Obtain a certificate signed by a publicly trusted CA (e.g. Let's Encrypt).",
                    score_deduction=DEDUCTIONS["SELF_SIGNED_LEAF"],
                )
            )

        # 2. Chain Verification Findings
        if chain_record:
            val_res = chain_record.get("validation_result")
            errors = chain_record.get("validation_errors", [])

            if val_res == "UNTRUSTED_ROOT":
                findings.append(
                    CertificateFinding(
                        code="RULE_UNTRUSTED_ROOT",
                        title="Untrusted Trust Anchor Root",
                        severity=FindingSeverity.HIGH,
                        description="Certificate chain terminates at a root CA not present in the specified root store (e.g., Mozilla CCADB).",
                        evidence={
                            "root_anchor": chain_record.get("trust_anchor_name"),
                            "trust_store": chain_record.get("trust_store_identifier"),
                        },
                        recommendation="Ensure the issuing CA is accredited in standard operating system trust programs.",
                        score_deduction=DEDUCTIONS["UNTRUSTED_ROOT"],
                    )
                )
            elif val_res == "INCOMPLETE_CHAIN":
                findings.append(
                    CertificateFinding(
                        code="RULE_INCOMPLETE_CHAIN",
                        title="Incomplete Intermediate Certificate Chain",
                        severity=FindingSeverity.HIGH,
                        description="One or more intermediate CA certificates were omitted by the TLS server. Clients without cached intermediates will fail validation.",
                        evidence={"chain_length": chain_record.get("chain_length"), "validation_errors": errors},
                        recommendation="Configure the TLS server to bundle all required intermediate certificates.",
                        score_deduction=DEDUCTIONS["INCOMPLETE_CHAIN"],
                    )
                )
            elif val_res == "EXPIRED_CHAIN_NODE":
                findings.append(
                    CertificateFinding(
                        code="RULE_EXPIRED_CHAIN_NODE",
                        title="Expired Intermediate or Root CA in Chain",
                        severity=FindingSeverity.HIGH,
                        description="An intermediate or root CA certificate in the certification path has expired relative to the verification time.",
                        evidence={"validation_errors": errors},
                        recommendation="Update server intermediate certificate bundle to use unexpired CA certificates.",
                        score_deduction=DEDUCTIONS["EXPIRED_CHAIN_NODE"],
                    )
                )
            elif val_res == "BASIC_CONSTRAINTS_VIOLATION":
                findings.append(
                    CertificateFinding(
                        code="RULE_CHAIN_BASIC_CONSTRAINTS_VIOLATION",
                        title="Issuing CA Violates Basic Constraints",
                        severity=FindingSeverity.HIGH,
                        description="An intermediate certificate issuing subordinate certificates lacks CA basic constraints (is_ca=True) or keyCertSign usage.",
                        evidence={"validation_errors": errors},
                        recommendation="Ensure all issuing intermediate certificates are properly designated CA certificates asserting keyCertSign.",
                        score_deduction=DEDUCTIONS["BASIC_CONSTRAINTS_VIOLATION"],
                    )
                )
            elif val_res == "PATH_LENGTH_EXCEEDED":
                findings.append(
                    CertificateFinding(
                        code="RULE_PATH_LENGTH_EXCEEDED",
                        title="Certificate Chain Exceeds Path Length Constraint",
                        severity=FindingSeverity.HIGH,
                        description="The certificate chain depth exceeds the pathLenConstraint asserted by an upstream CA.",
                        evidence={"validation_errors": errors},
                        recommendation="Reconfigure intermediate CA hierarchy to comply with path length limits.",
                        score_deduction=DEDUCTIONS["PATH_LENGTH_EXCEEDED"],
                    )
                )
            elif val_res == "INVALID_SIGNATURE":
                findings.append(
                    CertificateFinding(
                        code="RULE_INVALID_CHAIN_SIGNATURE",
                        title="Cryptographic Signature Verification Failed",
                        severity=FindingSeverity.CRITICAL,
                        description="Cryptographic signature verification failed along the certificate chain, indicating potential tampering or certificate corruption.",
                        evidence={"validation_errors": errors},
                        recommendation="Inspect and replace corrupted certificate files.",
                        score_deduction=DEDUCTIONS["INVALID_SIGNATURE"],
                    )
                )
            elif val_res == "VALID_TRUSTED":
                findings.append(
                    CertificateFinding(
                        code="RULE_VALID_CHAIN_TRUSTED",
                        title="Full Chain Validates to Trusted Root Anchor",
                        severity=FindingSeverity.INFO,
                        description=f"Certificate chain successfully verified up to trusted anchor: {chain_record.get('trust_anchor_name')}.",
                        evidence={
                            "chain_length": chain_record.get("chain_length"),
                            "trust_anchor": chain_record.get("trust_anchor_name"),
                        },
                        recommendation=None,
                        score_deduction=0,
                    )
                )

        return findings
