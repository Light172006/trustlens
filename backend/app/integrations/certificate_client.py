"""Integration client and typed interface for the TrustLens Certificate Analyzer Engine."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.config import settings

logger = logging.getLogger("trustlens.integrations.certificate")

_ENGINE_INSTANCE = None


class CertificateAnalyzerClient:
    """Client for invoking the TrustLens Certificate Analyzer Engine.

    Interprets leaf and intermediate X.509 certificates and TLS handshake telemetry,
    computing deterministic trust scores, CA/B forum policy evaluations, RFC 9525
    identity verifications, CT auditing, and optional ML compliance advisory.
    """

    def __init__(self) -> None:
        self._engine = None
        self._available = False
        try:
            from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine

            global _ENGINE_INSTANCE
            if _ENGINE_INSTANCE is None:
                _ENGINE_INSTANCE = CertificateAnalyzerEngine()
            self._engine = _ENGINE_INSTANCE
            self._available = True
            logger.info("TrustLens CertificateAnalyzerEngine initialized successfully.")
        except Exception as exc:
            logger.warning(
                f"CertificateAnalyzer package or engine failed to initialize: {exc}. "
                "Client will operate in fail-safe fallback mode."
            )

    @property
    def is_available(self) -> bool:
        """Returns True if the underlying CertificateAnalyzerEngine is loaded."""
        return self._available and self._engine is not None

    def analyze_endpoint_tls(
        self,
        certificate_der: bytes,
        target_hostname: str,
        port: int = 443,
        tls_protocol_version: str = "TLSv1.3",
        cipher_suite: str | None = None,
        presented_intermediates: list[bytes] | None = None,
        revocation_observation: dict[str, Any] | None = None,
        reference_time: datetime | None = None,
        include_ml_advisory: bool | None = None,
    ) -> Any:
        """Analyze a certificate within the context of an active TLS handshake."""
        # 1. Enforce size limits before passing to engine
        if len(certificate_der) > settings.TRUSTLENS_CERT_MAX_INPUT_BYTES:
            return self._create_resource_limit_assessment(
                size_bytes=len(certificate_der),
                target_hostname=target_hostname,
            )

        if not self.is_available:
            return self._create_inconclusive_assessment(
                reason="Certificate Analyzer engine unavailable",
                target_hostname=target_hostname,
            )

        try:
            from certificate_analyzer.api import analyze_endpoint_tls

            effective_ml_advisory = (
                include_ml_advisory
                if include_ml_advisory is not None
                else settings.TRUSTLENS_ENABLE_ML_ADVISORY
            )

            return analyze_endpoint_tls(
                certificate_der=certificate_der,
                target_hostname=target_hostname,
                port=port,
                tls_protocol_version=tls_protocol_version,
                cipher_suite=cipher_suite,
                presented_intermediates=presented_intermediates or [],
                revocation_observation=revocation_observation,
                reference_time=reference_time or datetime.now(UTC),
                engine=self._engine,
                include_ml_advisory=effective_ml_advisory,
            )
        except Exception as exc:
            logger.exception(f"Unhandled error in analyze_endpoint_tls: {exc}")
            return self._create_inconclusive_assessment(
                reason=f"Analysis error: {type(exc).__name__}",
                target_hostname=target_hostname,
            )

    def analyze_certificate(
        self,
        certificate_input: bytes | str | dict[str, Any],
        target_hostname: str | None = None,
        revocation_observation: dict[str, Any] | None = None,
        reference_time: datetime | None = None,
        include_ml_advisory: bool | None = None,
    ) -> Any:
        """Analyze a standalone DER, PEM, or parsed certificate record."""
        # Enforce size limits
        if isinstance(certificate_input, bytes | bytearray):
            if len(certificate_input) > settings.TRUSTLENS_CERT_MAX_INPUT_BYTES:
                return self._create_resource_limit_assessment(
                    size_bytes=len(certificate_input),
                    target_hostname=target_hostname,
                )
        elif isinstance(certificate_input, str):
            if len(certificate_input.encode("utf-8")) > settings.TRUSTLENS_CERT_MAX_INPUT_BYTES:
                return self._create_resource_limit_assessment(
                    size_bytes=len(certificate_input.encode("utf-8")),
                    target_hostname=target_hostname,
                )

        if not self.is_available:
            return self._create_inconclusive_assessment(
                reason="Certificate Analyzer engine unavailable",
                target_hostname=target_hostname,
            )

        try:
            from certificate_analyzer.api import analyze_certificate

            effective_ml_advisory = (
                include_ml_advisory
                if include_ml_advisory is not None
                else settings.TRUSTLENS_ENABLE_ML_ADVISORY
            )

            return analyze_certificate(
                certificate_input=certificate_input,
                target_hostname=target_hostname,
                revocation_observation=revocation_observation,
                reference_time=reference_time or datetime.now(UTC),
                engine=self._engine,
                include_ml_advisory=effective_ml_advisory,
            )
        except Exception as exc:
            logger.exception(f"Unhandled error in analyze_certificate: {exc}")
            return self._create_inconclusive_assessment(
                reason=f"Analysis error: {type(exc).__name__}",
                target_hostname=target_hostname,
            )

    def analyze_pem(
        self,
        pem_data: str,
        target_hostname: str | None = None,
        revocation_observation: dict[str, Any] | None = None,
        reference_time: datetime | None = None,
        include_ml_advisory: bool | None = None,
    ) -> Any:
        """Analyze a PEM certificate or fullchain bundle string."""
        return self.analyze_certificate(
            certificate_input=pem_data,
            target_hostname=target_hostname,
            revocation_observation=revocation_observation,
            reference_time=reference_time,
            include_ml_advisory=include_ml_advisory,
        )

    def _create_resource_limit_assessment(
        self, size_bytes: int, target_hostname: str | None = None
    ) -> Any:
        """Create a compliant assessment representing a resource limit rejection."""
        try:
            from certificate_analyzer.constants import CertificateVerdict
            from certificate_analyzer.schemas.assessment import CertificateAssessment
            from certificate_analyzer.schemas.findings import CertificateFinding, FindingSeverity

            finding = CertificateFinding(
                code="RULE_RESOURCE_LIMIT_EXCEEDED",
                title="Input Exceeds Resource Limits",
                severity=FindingSeverity.HIGH,
                description=(
                    f"Input certificate payload size of {size_bytes} bytes exceeds "
                    f"the maximum allowable ceiling of {settings.TRUSTLENS_CERT_MAX_INPUT_BYTES} bytes."
                ),
                evidence={
                    "size_bytes": size_bytes,
                    "max_allowed": settings.TRUSTLENS_CERT_MAX_INPUT_BYTES,
                },
                recommendation="Ensure certificate payload size conforms to standard Web PKI limits (<= 10 MB).",
                score_deduction=50,
            )
            return CertificateAssessment(
                certificate_sha256="",
                subject_dn="",
                issuer_dn="",
                verdict=CertificateVerdict.INCONCLUSIVE,
                trust_score=0,
                confidence=0.0,
                checks_completed=1,
                findings=[finding],
                recommendations=[finding.recommendation or ""],
                summary="Certificate rejected: payload exceeded maximum allowable size limits.",
                evaluated_at=datetime.now(UTC),
            )
        except Exception:
            return {
                "certificate_sha256": "",
                "subject_dn": "",
                "issuer_dn": "",
                "verdict": "INCONCLUSIVE",
                "trust_score": 0,
                "confidence": 0.0,
                "scoring_version": "cert_v1.0.0",
                "checks_completed": 1,
                "findings": [
                    {
                        "code": "RULE_RESOURCE_LIMIT_EXCEEDED",
                        "title": "Input Exceeds Resource Limits",
                        "severity": "HIGH",
                        "description": f"Input size {size_bytes} exceeds limit.",
                        "evidence": {"size_bytes": size_bytes},
                        "recommendation": "Provide valid certificate <= 10 MB.",
                        "score_deduction": 50,
                    }
                ],
                "recommendations": ["Provide valid certificate <= 10 MB."],
                "summary": "Certificate payload exceeded maximum allowable limits.",
                "evaluated_at": datetime.now(UTC).isoformat(),
            }

    def _create_inconclusive_assessment(
        self, reason: str, target_hostname: str | None = None
    ) -> Any:
        """Create a compliant inconclusive assessment."""
        try:
            from certificate_analyzer.constants import CertificateVerdict
            from certificate_analyzer.schemas.assessment import CertificateAssessment
            from certificate_analyzer.schemas.findings import CertificateFinding, FindingSeverity

            finding = CertificateFinding(
                code="RULE_MALFORMED_CERTIFICATE",
                title="Unparseable or Malformed Certificate",
                severity=FindingSeverity.CRITICAL,
                description=f"Analysis could not be concluded: {reason}.",
                evidence={"reason": reason, "target_hostname": target_hostname},
                recommendation="Verify input is a valid ASN.1 DER or PEM X.509 certificate.",
                score_deduction=100,
            )
            return CertificateAssessment(
                certificate_sha256="",
                subject_dn="",
                issuer_dn="",
                verdict=CertificateVerdict.INCONCLUSIVE,
                trust_score=0,
                confidence=0.0,
                checks_completed=0,
                findings=[finding],
                recommendations=[finding.recommendation or ""],
                summary=f"Certificate assessment inconclusive: {reason}.",
                evaluated_at=datetime.now(UTC),
            )
        except Exception:
            return {
                "certificate_sha256": "",
                "subject_dn": "",
                "issuer_dn": "",
                "verdict": "INCONCLUSIVE",
                "trust_score": 0,
                "confidence": 0.0,
                "scoring_version": "cert_v1.0.0",
                "checks_completed": 0,
                "findings": [
                    {
                        "code": "RULE_MALFORMED_CERTIFICATE",
                        "title": "Unparseable or Malformed Certificate",
                        "severity": "CRITICAL",
                        "description": reason,
                        "evidence": {"reason": reason},
                        "recommendation": "Verify input is a valid ASN.1 DER or PEM certificate.",
                        "score_deduction": 100,
                    }
                ],
                "recommendations": ["Verify input is a valid ASN.1 DER or PEM certificate."],
                "summary": f"Certificate assessment inconclusive: {reason}.",
                "evaluated_at": datetime.now(UTC).isoformat(),
            }


certificate_client = CertificateAnalyzerClient()
