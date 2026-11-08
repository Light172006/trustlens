"""Feature extraction engine for X.509 certificate intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_analyzer.rules.policy import CABFPolicyEvaluator
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures


class CertificateFeatureExtractor:
    """Extracts typed feature vectors from certificate records, chains, and observations."""

    @classmethod
    def extract(
        cls,
        cert_record: Dict[str, Any],
        chain_record: Optional[Dict[str, Any]] = None,
        context: Optional[EndpointTLSContext] = None,
        reference_time: Optional[datetime] = None,
    ) -> CertificateFeatures:
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        # 1. Cryptographic
        pub_key = cert_record.get("public_key", {})
        algo = pub_key.get("algorithm", "UNKNOWN").upper()
        key_size = pub_key.get("key_size_bits", 0)
        key_sec = pub_key.get("security_classification", "ACCEPTABLE")

        sig = cert_record.get("signature", {})
        sig_algo = sig.get("algorithm", "UNKNOWN")
        sig_sec = sig.get("security_classification", "ACCEPTABLE")
        sig_hash = sig.get("hash_algorithm", "")

        is_rsa = "RSA" in algo
        is_ecdsa = "ECDSA" in algo
        is_ed25519 = "ED25519" in algo
        is_weak_key = key_sec in ("INSECURE", "DEPRECATED")

        is_sha1 = "SHA1" in sig_hash.upper() or "SHA-1" in sig_algo.upper()
        is_md5 = "MD5" in sig_hash.upper() or "MD5" in sig_algo.upper()
        is_secure_sig = sig_sec == "SECURE"

        # 2. Temporal
        val = cert_record.get("validity", {})
        not_before_str = cert_record.get("not_before") or val.get("not_before", "")
        not_after_str = cert_record.get("not_after") or val.get("not_after", "")

        not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))
        not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))

        validity_days = cert_record.get("validity_duration_days") or val.get("validity_duration_days", 0.0)
        days_since_issuance = round((reference_time - not_before).total_seconds() / 86400.0, 2)
        days_until_expiry = round((not_after - reference_time).total_seconds() / 86400.0, 2)

        is_expired = reference_time > not_after
        is_not_yet_valid = reference_time < not_before
        is_short_lived = validity_days <= 90.0

        # 3. Domain & Identity (RFC 9525)
        dom_id = cert_record.get("domain_identity", {})
        dns_sans = dom_id.get("dns_san_entries", [])
        ip_sans = dom_id.get("ip_san_entries", [])
        sans = dom_id.get("subject_alternative_names", [])
        san_count = len(sans)
        has_san = san_count > 0
        has_wildcard = dom_id.get("has_wildcard", False) or any("*" in s for s in sans)
        has_ip = len(ip_sans) > 0

        matches_host = None
        if context and context.target_hostname:
            matched, _, _ = RFC9525IdentityVerifier.verify(
                reference_identity=context.target_hostname,
                dns_sans=dns_sans,
                ip_sans=ip_sans,
            )
            matches_host = matched

        # 4. Hierarchy & Chain
        exts = cert_record.get("extensions", {})
        bc = exts.get("basic_constraints", {})
        is_ca = bc.get("is_ca", False)
        subj_dn = cert_record.get("subject_dn", "")
        iss_dn = cert_record.get("issuer_dn", "")
        is_self_signed = (subj_dn == iss_dn)

        chain_length = 1
        is_chain_complete = False
        has_trusted_anchor = False

        if chain_record:
            chain_length = chain_record.get("chain_length", 1)
            is_chain_complete = chain_record.get("is_complete", False)
            has_trusted_anchor = chain_record.get("has_trusted_anchor", False)

        # 5. Revocation & Transparency
        crl_dps = exts.get("crl_distribution_points", [])
        aia = exts.get("authority_information_access", {})
        ocsp_urls = aia.get("ocsp_urls", [])

        scts = exts.get("signed_certificate_timestamps", [])
        sct_count = len(scts)
        has_scts = sct_count > 0

        # 6. Policy Checks
        kus = exts.get("key_usage", [])
        is_ca_constraint_compliant = True
        if is_ca and ("key_cert_sign" not in kus and len(kus) > 0):
            is_ca_constraint_compliant = False
        elif not is_ca and ("key_cert_sign" in kus):
            is_ca_constraint_compliant = False

        ekus = exts.get("extended_key_usage", [])
        is_eku_compliant = True
        if cert_record.get("certificate_type") == "LEAF" and ekus:
            if "serverAuth" not in ekus and "anyExtendedKeyUsage" not in ekus:
                is_eku_compliant = False

        # CA/B Forum v2.3.1 policy evaluation (issuance date-aware)
        policy_res = CABFPolicyEvaluator.evaluate(
            cert_record=cert_record,
            not_before=not_before,
            reference_time=reference_time,
            is_ca=is_ca,
            is_self_signed=is_self_signed,
        )
        is_cabf_validity_compliant = (
            policy_res["validity_compliant"] if policy_res["validity_compliant"] is not None else True
        )
        cabf_max_allowed = policy_res.get("max_validity_days_allowed")
        policy_applicability = policy_res.get("applicability", "APPLICABLE")

        return CertificateFeatures(
            public_key_algorithm=algo,
            key_size_bits=key_size,
            is_rsa=is_rsa,
            is_ecdsa=is_ecdsa,
            is_ed25519=is_ed25519,
            is_weak_key=is_weak_key,
            signature_algorithm=sig_algo,
            is_sha1_signature=is_sha1,
            is_md5_signature=is_md5,
            is_secure_signature=is_secure_sig,
            validity_duration_days=validity_days,
            days_since_issuance=days_since_issuance,
            days_until_expiry=days_until_expiry,
            is_expired=is_expired,
            is_not_yet_valid=is_not_yet_valid,
            is_short_lived=is_short_lived,
            has_san=has_san,
            san_count=san_count,
            has_wildcard_san=has_wildcard,
            has_ip_san=has_ip,
            matches_tested_hostname=matches_host,
            is_ca=is_ca,
            is_self_signed=is_self_signed,
            chain_length=chain_length,
            is_chain_complete=is_chain_complete,
            has_trusted_anchor=has_trusted_anchor,
            has_crl_distribution_points=len(crl_dps) > 0,
            has_ocsp_aia=len(ocsp_urls) > 0,
            has_scts=has_scts,
            sct_count=sct_count,
            is_cabf_validity_compliant=is_cabf_validity_compliant,
            cabf_max_allowed_validity_days=cabf_max_allowed,
            policy_applicability=policy_applicability,
            is_ca_constraint_compliant=is_ca_constraint_compliant,
            is_eku_compliant=is_eku_compliant,
        )
