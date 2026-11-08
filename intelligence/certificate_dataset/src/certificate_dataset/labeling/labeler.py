"""Multi-dimensional security and policy labeling engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from certificate_dataset.normalization.canonicalizer import Canonicalizer


class CertificateLabeler:
    """Computes multi-dimensional labels and policy compliance evaluations."""

    LABELING_VERSION = "1.0.0"

    def __init__(self, policy_config_path: Optional[Path] = None):
        if policy_config_path is None:
            policy_config_path = (
                Path(__file__).resolve().parent.parent.parent.parent
                / "config"
                / "policy_versions.yaml"
            )
        self.policy_config_path = Path(policy_config_path)
        self.policy_data: Dict[str, Any] = {}
        self.load_policy_config()

    def load_policy_config(self) -> None:
        if self.policy_config_path.exists():
            with open(self.policy_config_path, "r", encoding="utf-8") as f:
                self.policy_data = yaml.safe_load(f)

    def evaluate(
        self,
        cert_record: Dict[str, Any],
        reference_time: Optional[datetime] = None,
        target_hostname: Optional[str] = None,
        chain_record: Optional[Dict[str, Any]] = None,
        revocation_record: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates certificate record at a specific reference timestamp against multi-dimensional criteria."""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        # 1. PARSE_VALID
        parse_valid = "PASS" if cert_record.get("record_quality_status") in ("VALID_PARSED", "PARSE_WARNING") else "FAIL"

        # 2, 3, 4. Temporal evaluation
        not_before_str = cert_record.get("not_before") or cert_record["validity"]["not_before"]
        not_after_str = cert_record.get("not_after") or cert_record["validity"]["not_after"]
        not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))

        is_expired = reference_time > not_after
        is_not_yet_valid = reference_time < not_before
        is_time_valid = not is_expired and not is_not_yet_valid

        expired_label = "PASS" if is_expired else "FAIL"
        not_yet_valid_label = "PASS" if is_not_yet_valid else "FAIL"
        time_valid_label = "PASS" if is_time_valid else "FAIL"

        # 5. HOSTNAME_MATCH
        hostname_match_label = "NOT_CHECKED"
        matched_san = None
        if target_hostname:
            hostname_match_label = "FAIL"
            clean_host, _ = Canonicalizer.normalize_domain(target_hostname)
            sans = cert_record.get("domain_identity", {}).get("subject_alternative_names", [])
            for san in sans:
                san_clean, _ = Canonicalizer.normalize_domain(san)
                if self._match_hostname(clean_host, san_clean):
                    hostname_match_label = "PASS"
                    matched_san = san
                    break

        # 6, 7. Chain Evaluation
        chain_trusted_label = "NOT_CHECKED"
        chain_incomplete_label = "NOT_CHECKED"
        chain_err = None
        trust_store_name = None
        if chain_record:
            trust_store_name = chain_record.get("trust_store_identifier")
            val_res = chain_record.get("validation_result", "")
            if val_res == "VALID_TRUSTED":
                chain_trusted_label = "PASS"
                chain_incomplete_label = "FAIL"
            elif val_res == "INCOMPLETE_CHAIN":
                chain_trusted_label = "FAIL"
                chain_incomplete_label = "PASS"
                chain_err = "INCOMPLETE_CHAIN"
            else:
                chain_trusted_label = "FAIL"
                chain_incomplete_label = "FAIL"
                chain_err = val_res

        # 8. SELF_SIGNED
        subj_dn = cert_record.get("subject_dn", "")
        iss_dn = cert_record.get("issuer_dn", "")
        self_signed_label = "PASS" if subj_dn == iss_dn else "FAIL"

        # 9, 10. Revocation Evaluation
        revoked_label = "NOT_CHECKED"
        revocation_unknown_label = "PASS"
        rev_reason = None
        if revocation_record:
            norm_rev = revocation_record.get("normalized_status")
            if norm_rev == "REVOKED":
                revoked_label = "PASS"
                revocation_unknown_label = "FAIL"
                rev_reason = revocation_record.get("revocation_reason")
            elif norm_rev == "GOOD":
                revoked_label = "FAIL"
                revocation_unknown_label = "FAIL"
            else:
                revoked_label = "FAIL"
                revocation_unknown_label = "PASS"

        # 11. WEAK_PUBLIC_KEY
        key_sec = cert_record.get("public_key", {}).get("security_classification", "ACCEPTABLE")
        weak_key_label = "PASS" if key_sec in ("INSECURE", "DEPRECATED") else "FAIL"
        key_reason = None if weak_key_label == "FAIL" else f"Key security evaluated as {key_sec}"

        # 12. WEAK_SIGNATURE
        sig_sec = cert_record.get("signature", {}).get("security_classification", "ACCEPTABLE")
        weak_sig_label = "PASS" if sig_sec in ("INSECURE", "DEPRECATED") else "FAIL"
        sig_reason = None if weak_sig_label == "FAIL" else f"Signature security evaluated as {sig_sec}"

        # 13. SAN_PRESENT
        san_count = cert_record.get("domain_identity", {}).get("san_count", 0)
        san_present_label = "PASS" if san_count > 0 else "FAIL"

        # 14. CA_CONSTRAINT_VALID
        exts = cert_record.get("extensions", {})
        bc = exts.get("basic_constraints", {})
        is_ca = bc.get("is_ca", False)
        kus = exts.get("key_usage", [])
        if is_ca:
            ca_constraint_valid = "PASS" if ("key_cert_sign" in kus or len(kus) == 0) else "FAIL"
        else:
            ca_constraint_valid = "PASS" if "key_cert_sign" not in kus else "FAIL"

        # 15. EKU_PROFILE_VALID
        ekus = exts.get("extended_key_usage", [])
        # For TLS server certificates, serverAuth should be present (or anyExtendedKeyUsage)
        if cert_record.get("certificate_type") == "LEAF":
            eku_valid = "PASS" if (not ekus or "serverAuth" in ekus or "anyExtendedKeyUsage" in ekus) else "FAIL"
        else:
            eku_valid = "PASS"

        # 16. POLICY_COMPLIANT
        policy_eval = self._evaluate_policy(cert_record, not_before, reference_time)
        policy_compliant_label = "PASS" if (policy_eval["validity_period_compliant"] and policy_eval["cryptographic_profile_compliant"]) else "FAIL"

        labels: Dict[str, str] = {
            "PARSE_VALID": parse_valid,
            "TIME_VALID": time_valid_label,
            "EXPIRED": expired_label,
            "NOT_YET_VALID": not_yet_valid_label,
            "HOSTNAME_MATCH": hostname_match_label,
            "CHAIN_TRUSTED": chain_trusted_label,
            "CHAIN_INCOMPLETE": chain_incomplete_label,
            "SELF_SIGNED": self_signed_label,
            "REVOKED": revoked_label,
            "REVOCATION_UNKNOWN": revocation_unknown_label,
            "WEAK_PUBLIC_KEY": weak_key_label,
            "WEAK_SIGNATURE": weak_sig_label,
            "SAN_PRESENT": san_present_label,
            "CA_CONSTRAINT_VALID": ca_constraint_valid,
            "EKU_PROFILE_VALID": eku_valid,
            "POLICY_COMPLIANT": policy_compliant_label,
        }

        return {
            "certificate_sha256_fingerprint": cert_record["sha256_fingerprint"],
            "reference_observation_timestamp": reference_time.isoformat(),
            "labels": labels,
            "policy_evaluation": policy_eval,
            "evidence": {
                "tested_hostname": target_hostname,
                "matched_san": matched_san,
                "trust_store_used": trust_store_name,
                "chain_validation_error": chain_err,
                "revocation_reason": rev_reason,
                "key_security_reason": key_reason,
                "signature_security_reason": sig_reason,
            },
            "labeling_version": self.LABELING_VERSION,
        }

    def _evaluate_policy(
        self,
        cert_record: Dict[str, Any],
        not_before: datetime,
        reference_time: datetime,
    ) -> Dict[str, Any]:
        """Evaluates date-dependent validity duration and crypto requirements at issuance time."""
        duration_days = cert_record.get("validity_duration_days", 0.0)

        # Default rules
        applicable_rule_id = "CABF_BASELINE_DEFAULT"
        max_allowed_days = 398.0

        for rule in self.policy_data.get("validity_duration_rules", []):
            start = datetime.fromisoformat(rule["effective_start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(rule["effective_end"].replace("Z", "+00:00"))
            if start <= not_before <= end:
                applicable_rule_id = rule["rule_id"]
                max_allowed_days = float(rule["max_validity_days"])
                break

        # Validity duration check
        validity_compliant = duration_days <= (max_allowed_days + 1.0)  # 1 day grace for leap second / timezone boundary

        # Cryptographic check
        key_sec = cert_record.get("public_key", {}).get("security_classification", "ACCEPTABLE")
        sig_sec = cert_record.get("signature", {}).get("security_classification", "ACCEPTABLE")
        crypto_compliant = (key_sec in ("SECURE", "ACCEPTABLE")) and (sig_sec in ("SECURE", "ACCEPTABLE"))

        return {
            "applicable_policy_rule_id": applicable_rule_id,
            "policy_source": "CA/Browser Forum TLS Baseline Requirements",
            "policy_version": self.policy_data.get("standards", {}).get("cabf_baseline_requirements", {}).get("current_version", "2.0.8"),
            "certificate_issuance_date": not_before.isoformat(),
            "evaluation_timestamp": reference_time.isoformat(),
            "max_validity_days_allowed": max_allowed_days,
            "actual_validity_days": duration_days,
            "validity_period_compliant": validity_compliant,
            "cryptographic_profile_compliant": crypto_compliant,
        }

    @staticmethod
    def _match_hostname(hostname: str, san_pattern: str) -> bool:
        """Matches a target hostname against a SAN pattern complying with RFC 6125."""
        h = hostname.lower().strip().rstrip(".")
        p = san_pattern.lower().strip().rstrip(".")

        if h == p:
            return True

        if p.startswith("*."):
            suffix = p[2:]
            # e.g. *.example.com cannot match example.com
            if h == suffix:
                return False
            # Check single-level wildcard match (foo.example.com matches, foo.bar.example.com does not)
            parts_h = h.split(".")
            parts_p = suffix.split(".")
            if len(parts_h) == len(parts_p) + 1:
                return h.endswith("." + suffix)

        return False

