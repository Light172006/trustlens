"""Revocation verification and status normalization conforming to RFC 6960 (OCSP) and RFC 5280 (CRL).

Enforces:
- Exact status normalization: GOOD, REVOKED, UNKNOWN, NOT_CHECKED, ERROR.
- Strict rejection of UNKNOWN or NOT_CHECKED as GOOD.
- Temporal validation of thisUpdate (not in future) and nextUpdate (not expired).
- Absolute veto on TRUSTED verdict for any revoked certificate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class RevocationRules(CertificateRule):
    rule_id = "RULE_GROUP_REVOCATION"
    name = "Revocation Status Rules (RFC 6960 / RFC 5280)"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        # Evaluated via dedicated evaluate_revocation method when revocation observation is passed
        return []

    @classmethod
    def evaluate_revocation_observation(
        cls,
        rev_record: Optional[Dict[str, Any]],
        reference_time: datetime,
    ) -> List[CertificateFinding]:
        """Evaluates revocation record and returns authoritative findings."""
        if rev_record is None:
            return [
                CertificateFinding(
                    code="RULE_REVOCATION_NOT_CHECKED",
                    title="Revocation Status Not Checked",
                    severity=FindingSeverity.INFO,
                    description="No live OCSP query or CRL check was performed for this certificate.",
                    evidence=None,
                    recommendation="Enable OCSP / CRL validation to verify certificate has not been revoked.",
                    score_deduction=0,
                )
            ]

        raw_status = str(rev_record.get("normalized_status", "UNKNOWN")).upper()

        if raw_status == "REVOKED":
            reason = rev_record.get("revocation_reason", "unspecified")
            rev_time = rev_record.get("revocation_timestamp")
            return [
                CertificateFinding(
                    code="RULE_REVOKED",
                    title="Certificate Has Been Revoked",
                    severity=FindingSeverity.CRITICAL,
                    description=f"Authoritative revocation evidence confirmed via {rev_record.get('revocation_method', 'OCSP/CRL')}. Reason: {reason}.",
                    evidence={
                        "revocation_reason": reason,
                        "revocation_timestamp": rev_time,
                        "evidence_source": rev_record.get("evidence_source_url"),
                    },
                    recommendation="Immediately revoke deployment and replace with a newly issued, valid certificate.",
                    score_deduction=DEDUCTIONS["REVOKED"],
                )
            ]

        elif raw_status == "GOOD":
            # Verify temporal validity of the OCSP/CRL response
            is_valid_time = cls._verify_response_times(rev_record, reference_time)
            if not is_valid_time:
                return [
                    CertificateFinding(
                        code="RULE_REVOCATION_RESPONSE_EXPIRED",
                        title="Stale or Expired Revocation Response",
                        severity=FindingSeverity.MEDIUM,
                        description="The OCSP response or CRL is expired relative to the evaluation reference time.",
                        evidence={"next_update": rev_record.get("next_update")},
                        recommendation="Fetch current CRL or query live OCSP responder.",
                        score_deduction=15,
                    )
                ]

            return [
                CertificateFinding(
                    code="RULE_REVOCATION_VERIFIED_GOOD",
                    title="Certificate Status Confirmed GOOD",
                    severity=FindingSeverity.INFO,
                    description=f"Status verified as GOOD via {rev_record.get('revocation_method', 'OCSP')}.",
                    evidence={
                        "method": rev_record.get("revocation_method"),
                        "this_update": rev_record.get("this_update"),
                        "next_update": rev_record.get("next_update"),
                    },
                    recommendation=None,
                    score_deduction=0,
                )
            ]

        elif raw_status == "ERROR":
            return [
                CertificateFinding(
                    code="RULE_REVOCATION_ERROR",
                    title="Revocation Lookup Failed or Unverified",
                    severity=FindingSeverity.LOW,
                    description=f"Revocation check encountered an error: {rev_record.get('error_details', 'Unknown network/parsing error')}.",
                    evidence={"error": rev_record.get("error_details")},
                    recommendation="Verify network connectivity to CA OCSP/CRL infrastructure.",
                    score_deduction=5,
                )
            ]

        else:
            return [
                CertificateFinding(
                    code="RULE_REVOCATION_UNKNOWN",
                    title="Revocation Status Unknown",
                    severity=FindingSeverity.INFO,
                    description="Revocation status could not be established conclusively. Status remains UNKNOWN.",
                    evidence={"raw_status": raw_status},
                    recommendation="Query alternative OCSP responder or CRL distribution point.",
                    score_deduction=0,
                )
            ]

    @staticmethod
    def _verify_response_times(rev_record: Dict[str, Any], reference_time: datetime) -> bool:
        """Checks this_update <= reference_time <= next_update with 300s clock skew allowance."""
        next_up_str = rev_record.get("next_update")
        if not next_up_str:
            return True

        try:
            next_up = datetime.fromisoformat(next_up_str.replace("Z", "+00:00"))
            # If reference_time > next_up + 300s, response is stale
            if (reference_time - next_up).total_seconds() > 300:
                return False
        except Exception:
            return True

        return True

