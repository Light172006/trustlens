"""Master analyzer engine for TrustLens Certificate Intelligence."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from certificate_analyzer.constants import CURRENT_CERT_SCORING_VERSION, CertificateVerdict, FindingSeverity
from certificate_analyzer.engine.path_validator import CertificationPathValidator
from certificate_analyzer.features.extractor import CertificateFeatureExtractor
from certificate_analyzer.rules.engine import CertificateRuleEngine
from certificate_analyzer.rules.identity_rfc9525 import RFC9525IdentityVerifier
from certificate_analyzer.rules.policy import CABFPolicyEvaluator
from certificate_analyzer.schemas.assessment import CertificateAssessment
from certificate_analyzer.schemas.context import EndpointTLSContext
from certificate_analyzer.schemas.features import CertificateFeatures
from certificate_analyzer.schemas.findings import CertificateFinding
from certificate_analyzer.scoring.engine import CertificateScoringEngine
from certificate_dataset.normalization.canonicalizer import Canonicalizer
from certificate_dataset.parsing.parser import X509CertificateParser
from certificate_dataset.trust_stores.root_store import TrustStoreManager
from cryptography import x509


class CertificateAnalyzerEngine:
    """Master engine orchestrating certificate parsing, chain resolution, feature extraction, rule execution, and scoring."""

    MAX_INPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum input size
    MAX_BUNDLE_CERTS: int = 50                 # Maximum certificates allowed in a single bundle
    MAX_SAN_COUNT: int = 10000                 # Maximum allowable SAN count

    def __init__(
        self,
        trust_store_manager: Optional[TrustStoreManager] = None,
        rule_engine: Optional[CertificateRuleEngine] = None,
        ml_advisor: Optional[Any] = None,
    ):
        self.trust_store = trust_store_manager or TrustStoreManager()
        if self.trust_store.total_roots() == 0:
            self.trust_store.load_from_certifi()

        self.rule_engine = rule_engine or CertificateRuleEngine()

        self.ml_advisor = ml_advisor
        if self.ml_advisor is None:
            try:
                from certificate_analyzer.ml.inference import CertificateMLAdvisor
                advisor = CertificateMLAdvisor()
                if advisor.is_ready:
                    self.ml_advisor = advisor
            except Exception:
                self.ml_advisor = None

    def analyze(
        self,
        certificate_input: Union[bytes, str, Dict[str, Any]],
        context: Optional[EndpointTLSContext] = None,
        revocation_observation: Optional[Dict[str, Any]] = None,
        reference_time: Optional[datetime] = None,
        include_ml_advisory: bool = False,
    ) -> CertificateAssessment:
        """Executes full digital trust and security analysis on a certificate input."""
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        # 1. Parse or Normalize Input
        cert_record: Dict[str, Any]
        cert_obj: Optional[x509.Certificate] = None
        presented_intermediates_objs: List[x509.Certificate] = []

        if context and context.presented_intermediates:
            for der in context.presented_intermediates:
                try:
                    presented_intermediates_objs.append(x509.load_der_x509_certificate(der))
                except Exception:
                    pass

        if isinstance(certificate_input, dict):
            cert_record = certificate_input
            if not cert_record:
                return self._create_empty_input_assessment(reference_time)
            if "der_base64" in cert_record:
                der_bytes = base64.b64decode(cert_record["der_base64"])
                cert_obj = x509.load_der_x509_certificate(der_bytes)
        elif isinstance(certificate_input, (bytes, str)):
            input_bytes = certificate_input.encode("utf-8") if isinstance(certificate_input, str) else certificate_input

            # Security limit: Input byte length
            if len(input_bytes) == 0:
                return self._create_empty_input_assessment(reference_time)
            if len(input_bytes) > self.MAX_INPUT_BYTES:
                return self._create_resource_limit_assessment(
                    f"Input size ({len(input_bytes)} bytes) exceeds {self.MAX_INPUT_BYTES} byte limit",
                    reference_time,
                )

            try:
                # Check for multiple PEM blocks (bundle / fullchain)
                if b"-----BEGIN CERTIFICATE-----" in input_bytes:
                    text = input_bytes.decode("utf-8", errors="replace")
                    pem_blocks = re.findall(
                        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        text,
                        re.DOTALL,
                    )
                    if len(pem_blocks) > self.MAX_BUNDLE_CERTS:
                        return self._create_resource_limit_assessment(
                            f"PEM bundle contains {len(pem_blocks)} certificates, exceeding maximum limit of {self.MAX_BUNDLE_CERTS}",
                            reference_time,
                        )

                    if len(pem_blocks) > 1:
                        # Intelligently resolve leaf and intermediate certificates
                        parsed_certs: List[Tuple[str, x509.Certificate]] = []
                        for block in pem_blocks:
                            try:
                                c = x509.load_pem_x509_certificate(block.encode("ascii"))
                                parsed_certs.append((block, c))
                            except Exception:
                                pass

                        if not parsed_certs:
                            return self._create_malformed_assessment("No valid X.509 certificates could be parsed from PEM bundle", reference_time)

                        # Identify plausible leaf candidates: not CA and not issuer of other certs in bundle
                        all_issuers = {c.issuer for _, c in parsed_certs}

                        def is_ca_cert(c: x509.Certificate) -> bool:
                            try:
                                bc = c.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value
                                return bool(bc.ca)
                            except x509.ExtensionNotFound:
                                return False

                        leaf_candidates = [
                            (block, c) for block, c in parsed_certs
                            if not is_ca_cert(c) and c.subject not in (all_issuers - {c.subject})
                        ]

                        chosen_leaf: Optional[Tuple[str, x509.Certificate]] = None

                        if len(leaf_candidates) == 1:
                            chosen_leaf = leaf_candidates[0]
                        elif len(leaf_candidates) > 1 and context and context.target_hostname:
                            # Match target_hostname against candidates
                            matching_candidates = []
                            for block, c in leaf_candidates:
                                dns_sans = []
                                ip_sans = []
                                try:
                                    san_ext = c.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                                    dns_sans = san_ext.get_values_for_type(x509.DNSName)
                                    ip_sans = [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)]
                                except x509.ExtensionNotFound:
                                    pass
                                matched, _, _ = RFC9525IdentityVerifier.verify(context.target_hostname, dns_sans, ip_sans)
                                if matched:
                                    matching_candidates.append((block, c))

                            if len(matching_candidates) == 1:
                                chosen_leaf = matching_candidates[0]
                            else:
                                return self._create_ambiguous_bundle_assessment(len(leaf_candidates), reference_time)
                        elif len(leaf_candidates) > 1:
                            # Multiple leaf candidates and no hostname to disambiguate
                            return self._create_ambiguous_bundle_assessment(len(leaf_candidates), reference_time)
                        else:
                            # If no non-CA leaves found, fall back to the first block
                            chosen_leaf = parsed_certs[0]

                        # Parse selected leaf
                        cert_record = X509CertificateParser.parse(
                            chosen_leaf[0].encode("ascii"),
                            observation_timestamp=reference_time.isoformat(),
                        )
                        cert_record = Canonicalizer.normalize_record(cert_record)
                        cert_obj = chosen_leaf[1]

                        # Remaining certificates in bundle become presented intermediates
                        for block, c in parsed_certs:
                            if c != chosen_leaf[1] and c not in presented_intermediates_objs:
                                presented_intermediates_objs.append(c)

                    elif len(pem_blocks) == 1:
                        cert_record = X509CertificateParser.parse(
                            pem_blocks[0].encode("ascii"),
                            observation_timestamp=reference_time.isoformat(),
                        )
                        cert_record = Canonicalizer.normalize_record(cert_record)
                        der_bytes = base64.b64decode(cert_record["der_base64"])
                        cert_obj = x509.load_der_x509_certificate(der_bytes)
                    else:
                        return self._create_malformed_assessment("No valid PEM certificate block found", reference_time)
                else:
                    # Treat as raw DER
                    cert_record = X509CertificateParser.parse(
                        input_bytes,
                        observation_timestamp=reference_time.isoformat(),
                    )
                    cert_record = Canonicalizer.normalize_record(cert_record)
                    der_bytes = base64.b64decode(cert_record["der_base64"])
                    cert_obj = x509.load_der_x509_certificate(der_bytes)
            except Exception as e:
                return self._create_malformed_assessment(str(e), reference_time)
        else:
            return self._create_malformed_assessment("Unsupported input format", reference_time)

        # Security limit: SAN count
        san_count = cert_record.get("domain_identity", {}).get("san_count", 0)
        if san_count > self.MAX_SAN_COUNT:
            return self._create_resource_limit_assessment(
                f"SAN count ({san_count}) exceeds maximum allowable limit of {self.MAX_SAN_COUNT}",
                reference_time,
            )

        # 2. Build and Validate Certification Path (RFC 5280)
        chain_record: Optional[Dict[str, Any]] = None
        if cert_obj:
            ref_store = context.reference_store if context else "MOZILLA"
            chain_record = CertificationPathValidator.validate_path(
                leaf_cert=cert_obj,
                presented_intermediates=presented_intermediates_objs,
                trust_store=self.trust_store,
                reference_time=reference_time,
                store_name=ref_store,
            )

        # 3. Extract Features
        features: CertificateFeatures = CertificateFeatureExtractor.extract(
            cert_record=cert_record,
            chain_record=chain_record,
            context=context,
            reference_time=reference_time,
        )

        # 4. Execute Rule Engine
        findings: List[CertificateFinding] = self.rule_engine.evaluate_all(
            features=features,
            cert_record=cert_record,
            chain_record=chain_record,
            context=context,
            revocation_record=revocation_observation,
            reference_time=reference_time,
        )

        # 5. Score & Verdict
        verdict, trust_score, confidence = CertificateScoringEngine.calculate(
            findings=findings,
            features=features,
            is_malformed=False,
        )

        # 6. Policy Evaluation details (CA/B Forum v2.3.1)
        not_before_str = cert_record.get("not_before") or cert_record.get("validity", {}).get("not_before", "")
        try:
            not_before_dt = datetime.fromisoformat(not_before_str.replace("Z", "+00:00")) if not_before_str else reference_time
        except Exception:
            not_before_dt = reference_time

        policy_eval = cert_record.get("policy_evaluation") or CABFPolicyEvaluator.evaluate(
            cert_record=cert_record,
            not_before=not_before_dt,
            reference_time=reference_time,
            is_ca=features.is_ca,
            is_self_signed=features.is_self_signed,
        )

        # 7. Optional ML Advisory Enrichment (strictly advisory)
        ml_advisory_payload = None
        if include_ml_advisory and self.ml_advisor is not None:
            ml_advisory_payload = self.ml_advisor.predict_safe(cert_record)

        # 8. Formulate Executive Summary & Recommendations
        recommendations = [f.recommendation for f in findings if f.recommendation]
        summary = self._generate_summary(verdict, trust_score, findings, cert_record, context, chain_record)

        return CertificateAssessment(
            certificate_sha256=cert_record.get("sha256_fingerprint", "0" * 64),
            subject_dn=cert_record.get("subject_dn", ""),
            issuer_dn=cert_record.get("issuer_dn", ""),
            verdict=verdict,
            trust_score=trust_score,
            confidence=confidence,
            scoring_version=CURRENT_CERT_SCORING_VERSION,
            checks_completed=len(findings),
            findings=findings,
            features=features,
            policy_evaluation=policy_eval,
            ml_advisory=ml_advisory_payload,
            recommendations=recommendations,
            summary=summary,
            evaluated_at=reference_time,
        )

    def _create_malformed_assessment(self, error_msg: str, evaluated_at: datetime) -> CertificateAssessment:
        finding = CertificateFinding(
            code="RULE_MALFORMED_CERTIFICATE",
            title="Unparseable or Malformed Certificate",
            severity=FindingSeverity.CRITICAL,
            description=f"The supplied input could not be decoded as valid X.509 DER or PEM data: {error_msg}",
            evidence={"error": error_msg},
            recommendation="Supply a valid ASN.1 DER or PEM encoded X.509 certificate.",
            score_deduction=100,
        )
        return CertificateAssessment(
            certificate_sha256="0" * 64,
            subject_dn="UNKNOWN",
            issuer_dn="UNKNOWN",
            verdict=CertificateVerdict.INCONCLUSIVE,
            trust_score=0,
            confidence=0.0,
            scoring_version=CURRENT_CERT_SCORING_VERSION,
            checks_completed=1,
            findings=[finding],
            features=None,
            policy_evaluation=None,
            recommendations=["Verify certificate encoding and formatting."],
            summary=f"Analysis inconclusive: Certificate failed ASN.1 decoding ({error_msg}).",
            evaluated_at=evaluated_at,
        )

    def _create_empty_input_assessment(self, evaluated_at: datetime) -> CertificateAssessment:
        finding = CertificateFinding(
            code="RULE_MALFORMED_CERTIFICATE",
            title="Empty Certificate Data",
            severity=FindingSeverity.CRITICAL,
            description="The supplied certificate input is empty (0 bytes).",
            evidence={"error": "EMPTY_CERTIFICATE"},
            recommendation="Supply non-empty ASN.1 DER or PEM encoded X.509 certificate data.",
            score_deduction=100,
        )
        return CertificateAssessment(
            certificate_sha256="0" * 64,
            subject_dn="UNKNOWN",
            issuer_dn="UNKNOWN",
            verdict=CertificateVerdict.INCONCLUSIVE,
            trust_score=0,
            confidence=0.0,
            scoring_version=CURRENT_CERT_SCORING_VERSION,
            checks_completed=1,
            findings=[finding],
            features=None,
            policy_evaluation=None,
            recommendations=["Supply valid X.509 certificate data."],
            summary="Analysis inconclusive: Supplied certificate data is empty (0 bytes).",
            evaluated_at=evaluated_at,
        )

    def _create_ambiguous_bundle_assessment(self, num_leaves: int, evaluated_at: datetime) -> CertificateAssessment:
        finding = CertificateFinding(
            code="RULE_AMBIGUOUS_BUNDLE_MULTIPLE_LEAVES",
            title="Ambiguous Bundle: Multiple Plausible Leaf Certificates",
            severity=FindingSeverity.HIGH,
            description=f"The supplied PEM bundle contains {num_leaves} independent plausible leaf certificates without target hostname context to resolve ambiguity.",
            evidence={"leaf_candidates_count": num_leaves},
            recommendation="Supply a target_hostname to select the intended leaf, or isolate individual certificates for independent analysis.",
            score_deduction=50,
        )
        return CertificateAssessment(
            certificate_sha256="0" * 64,
            subject_dn="AMBIGUOUS",
            issuer_dn="AMBIGUOUS",
            verdict=CertificateVerdict.INCONCLUSIVE,
            trust_score=0,
            confidence=0.0,
            scoring_version=CURRENT_CERT_SCORING_VERSION,
            checks_completed=1,
            findings=[finding],
            features=None,
            policy_evaluation=None,
            recommendations=["Specify target_hostname or provide a single leaf certificate bundle."],
            summary=f"Analysis inconclusive: PEM bundle contains {num_leaves} plausible leaf certificates with ambiguous target.",
            evaluated_at=evaluated_at,
        )

    def _create_resource_limit_assessment(self, reason: str, evaluated_at: datetime) -> CertificateAssessment:
        finding = CertificateFinding(
            code="RULE_RESOURCE_LIMIT_EXCEEDED",
            title="Security Limit Exceeded (DoS Protection)",
            severity=FindingSeverity.CRITICAL,
            description=f"Certificate analysis rejected: {reason}.",
            evidence={"reason": reason},
            recommendation="Ensure certificate inputs adhere to documented production size boundaries.",
            score_deduction=100,
        )
        return CertificateAssessment(
            certificate_sha256="0" * 64,
            subject_dn="REJECTED",
            issuer_dn="REJECTED",
            verdict=CertificateVerdict.INCONCLUSIVE,
            trust_score=0,
            confidence=0.0,
            scoring_version=CURRENT_CERT_SCORING_VERSION,
            checks_completed=1,
            findings=[finding],
            features=None,
            policy_evaluation=None,
            recommendations=["Verify input size and compliance with maximum security thresholds."],
            summary=f"Analysis inconclusive: Security boundary exceeded ({reason}).",
            evaluated_at=evaluated_at,
        )

    @staticmethod
    def _generate_summary(
        verdict: CertificateVerdict,
        trust_score: int,
        findings: List[CertificateFinding],
        cert_record: Dict[str, Any],
        context: Optional[EndpointTLSContext],
        chain_record: Optional[Dict[str, Any]],
    ) -> str:
        cn = cert_record.get("subject", {}).get("common_name") or cert_record.get("subject_dn", "Certificate")
        issuer = cert_record.get("issuer", {}).get("common_name") or cert_record.get("issuer_dn", "Unknown CA")

        critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        warning_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)

        if verdict == CertificateVerdict.TRUSTED:
            host_note = f" for '{context.target_hostname}'" if context and context.target_hostname else " (endpoint identity not evaluated)"
            return (
                f"Certificate '{cn}' is TRUSTED (Score: {trust_score}/100){host_note}. Issued by '{issuer}' with robust "
                f"cryptographic parameters and valid trust anchor verification."
            )
        elif verdict == CertificateVerdict.WARNING:
            return (
                f"Certificate '{cn}' has WARNINGS (Score: {trust_score}/100). {warning_count} warning(s) detected. "
                f"Review chain configuration, upcoming expiration, or policy constraints."
            )
        else:
            top_defect = findings[0].title if findings else "Severe cryptographic or trust defect"
            return (
                f"Certificate '{cn}' is DISTRUSTED (Score: {trust_score}/100). {critical_count} critical and {high_count} high-severity "
                f"defect(s) identified. Primary issue: {top_defect}."
            )
