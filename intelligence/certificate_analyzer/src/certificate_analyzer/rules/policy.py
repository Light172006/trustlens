"""CA/Browser Forum Baseline Requirements v2.3.1 Policy Engine & Rules.

Implements versioned, issuance-date-aware CA/B Forum Baseline Requirements (v2.3.1):
- Evaluates subscriber certificate validity tiers strictly based on certificate issuance date:
  * Prior to March 15, 2026: 398 days max
  * March 15, 2026 - March 14, 2027: 200 days max
  * March 15, 2027 - March 14, 2029: 100 days max
  * From March 15, 2029 onwards: 47 days max
- Differentiates profiles: Root CAs, Intermediate CAs, and Private PKIs are designated NOT_APPLICABLE
  rather than incorrectly penalized for exceeding subscriber validity limits.
- Evaluates cryptographic security profile compliance (key size and signature algorithms).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from certificate_analyzer.constants import DEDUCTIONS, FindingSeverity
from certificate_analyzer.rules.base import CertificateRule
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding


class CABFPolicyEvaluator:
    """Evaluates CA/Browser Forum Baseline Requirements (v2.3.1) policies."""

    POLICY_NAME = "CA/Browser Forum Baseline Requirements for TLS Server Certificates"
    POLICY_VERSION = "2.3.1"

    # Explicit UTC date boundaries for TLS server subscriber validity limits
    TIER_2026_START = datetime(2026, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    TIER_2027_START = datetime(2027, 3, 15, 0, 0, 0, tzinfo=timezone.utc)
    TIER_2029_START = datetime(2029, 3, 15, 0, 0, 0, tzinfo=timezone.utc)

    # Legacy historical boundaries
    TIER_2020_START = datetime(2020, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    TIER_2018_START = datetime(2018, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    @classmethod
    def evaluate(
        cls,
        cert_record: Dict[str, Any],
        not_before: datetime,
        reference_time: Optional[datetime] = None,
        is_ca: bool = False,
        is_self_signed: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates certificate against CA/B Forum TLS Baseline Requirements v2.3.1."""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)

        duration_days = float(cert_record.get("validity_duration_days") or cert_record.get("validity", {}).get("validity_duration_days", 0.0))

        # 1. Determine Certificate Profile & Applicability
        if is_ca:
            profile = "ROOT_CA" if is_self_signed else "INTERMEDIATE_CA"
            applicability = "NOT_APPLICABLE"
            rule_id = "CABF_NOT_APPLICABLE_CA"
            max_days = None
            validity_compliant = None
            note = f"CA certificates ({profile}) are governed by Root Store policies; subscriber validity limits do not apply."
        else:
            profile = "TLS_SUBSCRIBER"
            applicability = "APPLICABLE"

            # Determine applicable issuance-date tier (v2.3.1)
            if not_before >= cls.TIER_2029_START:
                rule_id = "CABF_2029_47_DAYS"
                max_days = 47.0
            elif not_before >= cls.TIER_2027_START:
                rule_id = "CABF_2027_100_DAYS"
                max_days = 100.0
            elif not_before >= cls.TIER_2026_START:
                rule_id = "CABF_2026_200_DAYS"
                max_days = 200.0
            elif not_before >= cls.TIER_2020_START:
                rule_id = "CABF_398_DAYS"
                max_days = 398.0
            elif not_before >= cls.TIER_2018_START:
                rule_id = "CABF_825_DAYS"
                max_days = 825.0
            else:
                rule_id = "CABF_LEGACY_1185_DAYS"
                max_days = 1185.0

            # 1-day grace period for timezone and leap-second boundaries
            validity_compliant = duration_days <= (max_days + 1.0)
            note = f"Subscriber certificate evaluated against {rule_id} (allowed: <= {max_days:.0f} days, actual: {duration_days:.1f} days)."

        # 2. Cryptographic Profile Check
        pk = cert_record.get("public_key", {})
        sig = cert_record.get("signature", {})
        key_sec = pk.get("security_classification", "ACCEPTABLE")
        sig_sec = sig.get("security_classification", "ACCEPTABLE")
        crypto_compliant = (key_sec in ("SECURE", "ACCEPTABLE")) and (sig_sec in ("SECURE", "ACCEPTABLE"))

        overall_compliant = None
        if applicability == "APPLICABLE":
            overall_compliant = bool(validity_compliant and crypto_compliant)

        return {
            "policy_name": cls.POLICY_NAME,
            "policy_version": cls.POLICY_VERSION,
            "certificate_profile": profile,
            "applicability": applicability,
            "applicable_rule_id": rule_id,
            "certificate_issuance_date": not_before.isoformat(),
            "evaluation_date": reference_time.isoformat(),
            "max_validity_days_allowed": max_days,
            "actual_validity_days": duration_days,
            "validity_compliant": validity_compliant,
            "cryptographic_compliant": crypto_compliant,
            "overall_compliant": overall_compliant,
            "evaluation_notes": note,
        }


class PolicyRules(CertificateRule):
    rule_id = "RULE_GROUP_POLICY"
    name = "CA/Browser Forum & Policy Rules"

    def evaluate(
        self,
        features: CertificateFeatures,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
    ) -> List[CertificateFinding]:
        findings: List[CertificateFinding] = []

        # 1. CABF Maximum Validity Limit (Subscriber Certificates)
        if features.policy_applicability == "APPLICABLE":
            if not features.is_cabf_validity_compliant:
                max_allowed = features.cabf_max_allowed_validity_days or 398.0
                findings.append(
                    CertificateFinding(
                        code="RULE_CABF_MAX_VALIDITY_EXCEEDED",
                        title="Validity Duration Exceeds CA/Browser Forum Limit",
                        severity=FindingSeverity.MEDIUM,
                        description=(
                            f"Subscriber certificate validity duration ({features.validity_duration_days:.0f} days) "
                            f"exceeds the applicable CA/B Forum Baseline Requirements limit (maximum {max_allowed:.0f} days "
                            f"for certificates issued on or after the relevant policy date)."
                        ),
                        evidence={
                            "validity_duration_days": features.validity_duration_days,
                            "max_allowed_days": max_allowed,
                            "policy_version": CABFPolicyEvaluator.POLICY_VERSION,
                        },
                        recommendation=f"Reissue certificate with validity duration <= {max_allowed:.0f} days.",
                        score_deduction=DEDUCTIONS["CABF_MAX_VALIDITY_EXCEEDED"],
                    )
                )
        else:
            # Policy is NOT_APPLICABLE for CA certificates
            findings.append(
                CertificateFinding(
                    code="RULE_POLICY_NOT_APPLICABLE",
                    title="Subscriber Policy Not Applicable to CA Certificate",
                    severity=FindingSeverity.INFO,
                    description="Certificate is a Certificate Authority. Public TLS subscriber validity limits do not apply.",
                    evidence={"is_ca": features.is_ca},
                    recommendation=None,
                    score_deduction=0,
                )
            )

        # 2. Basic Constraints Consistency
        if not features.is_ca_constraint_compliant:
            findings.append(
                CertificateFinding(
                    code="RULE_CA_CONSTRAINT_VIOLATION",
                    title="Inconsistent Basic Constraints or Key Usage",
                    severity=FindingSeverity.MEDIUM,
                    description="Certificate basic constraints (is_ca) and keyCertSign key usage bits are inconsistent.",
                    evidence={"is_ca": features.is_ca},
                    recommendation="Ensure CA certificates assert keyCertSign and leaf certificates omit CA flags.",
                    score_deduction=DEDUCTIONS["CA_CONSTRAINT_VIOLATION"],
                )
            )

        # 3. Certificate Transparency (RFC 6962 / RFC 9162)
        if features.has_scts:
            findings.append(
                CertificateFinding(
                    code="RULE_CERTIFICATE_TRANSPARENCY_PRESENT",
                    title="Certificate Transparency SCTs Embedded",
                    severity=FindingSeverity.INFO,
                    description=(
                        f"Certificate contains {features.sct_count} embedded Signed Certificate Timestamp(s). "
                        f"SCT presence represents a signed promise to log by CT operators (RFC 6962); inclusion proof "
                        f"requires an explicit Merkle audit proof."
                    ),
                    evidence={"sct_count": features.sct_count},
                    recommendation=None,
                    score_deduction=0,
                )
            )
        else:
            if features.policy_applicability == "APPLICABLE":
                findings.append(
                    CertificateFinding(
                        code="RULE_NO_EMBEDDED_SCTS",
                        title="No Embedded Certificate Transparency Timestamps",
                        severity=FindingSeverity.INFO,
                        description="Certificate does not contain embedded SCTs (may be delivered via TLS extension or OCSP staple).",
                        evidence=None,
                        recommendation=None,
                        score_deduction=0,
                    )
                )

        return findings
