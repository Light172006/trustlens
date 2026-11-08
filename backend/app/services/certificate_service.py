"""Service for managing certificate security assessments and persistence."""

from __future__ import annotations

import base64
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EntityNotFoundException, ValidationError
from app.integrations.certificate_client import certificate_client
from app.models.certificate_scan import CertificateScan
from app.scanners.tls_scanner import tls_scanner
from app.scanners.url_validator import validate_and_canonicalize_url
from app.schemas.certificate import (
    CertificateAnalyzeRequest,
    CertificateAssessmentResponse,
    CertificateFindingItem,
    CertificateScanListResponse,
    CertificateScanSummaryItem,
)

logger = logging.getLogger("trustlens.services.certificate")


class CertificateService:
    """Service layer for certificate analysis, active TLS probing, and assessment queries."""

    async def analyze_certificate_request(
        self,
        db: AsyncSession,
        request: CertificateAnalyzeRequest,
        user_id: uuid.UUID | None = None,
    ) -> CertificateAssessmentResponse:
        """Execute certificate analysis from provided DER, PEM, or target endpoint hostname."""
        raw_assessment: Any = None
        target_host = request.target_hostname.strip() if request.target_hostname else None

        # 1. Option A: Binary DER (base64) provided
        if request.certificate_der_base64:
            try:
                der_bytes = base64.b64decode(request.certificate_der_base64)
            except Exception as exc:
                raise ValidationError(f"Invalid base64 encoding for certificate_der_base64: {exc}")

            intermediates_bytes: list[bytes] = []
            for item in request.presented_intermediates_base64:
                try:
                    intermediates_bytes.append(base64.b64decode(item))
                except Exception as exc:
                    logger.warning(f"Skipping malformed base64 intermediate: {exc}")

            if target_host:
                raw_assessment = certificate_client.analyze_endpoint_tls(
                    certificate_der=der_bytes,
                    target_hostname=target_host,
                    port=request.port,
                    tls_protocol_version=request.tls_protocol_version,
                    cipher_suite=request.cipher_suite,
                    presented_intermediates=intermediates_bytes,
                    revocation_observation=request.revocation_observation,
                    reference_time=request.reference_observation_timestamp,
                    include_ml_advisory=request.include_ml_advisory,
                )
            else:
                raw_assessment = certificate_client.analyze_certificate(
                    certificate_input=der_bytes,
                    target_hostname=None,
                    revocation_observation=request.revocation_observation,
                    reference_time=request.reference_observation_timestamp,
                    include_ml_advisory=request.include_ml_advisory,
                )

        # 2. Option B: PEM string provided
        elif request.certificate_pem:
            raw_assessment = certificate_client.analyze_pem(
                pem_data=request.certificate_pem,
                target_hostname=target_host,
                revocation_observation=request.revocation_observation,
                reference_time=request.reference_observation_timestamp,
                include_ml_advisory=request.include_ml_advisory,
            )

        # 3. Option C: Live endpoint hostname provided
        elif target_host:
            # Validate target host against SSRF/internal network restrictions
            try:
                validate_and_canonicalize_url(f"https://{target_host}")
            except Exception as exc:
                raise ValidationError(f"Invalid or prohibited target hostname: {exc}")

            # Run active TLS handshake scanner
            tls_result = tls_scanner.scan(host=target_host, port=request.port)
            if tls_result.raw_leaf_der:
                raw_assessment = certificate_client.analyze_endpoint_tls(
                    certificate_der=tls_result.raw_leaf_der,
                    target_hostname=target_host,
                    port=request.port,
                    tls_protocol_version=tls_result.protocol_version
                    or request.tls_protocol_version,
                    cipher_suite=tls_result.cipher_suite or request.cipher_suite,
                    presented_intermediates=tls_result.presented_intermediates_der,
                    revocation_observation=request.revocation_observation,
                    reference_time=request.reference_observation_timestamp,
                    include_ml_advisory=request.include_ml_advisory,
                )
            else:
                # Connection failed
                raw_assessment = certificate_client._create_inconclusive_assessment(
                    reason=tls_result.error_message
                    or f"Failed to establish TLS connection to {target_host}:{request.port}",
                    target_hostname=target_host,
                )

        else:
            raise ValidationError(
                "Must provide at least one of: certificate_der_base64, certificate_pem, or target_hostname."
            )

        # Convert assessment to dictionary
        if hasattr(raw_assessment, "model_dump"):
            payload = raw_assessment.model_dump(mode="json")
        elif isinstance(raw_assessment, dict):
            payload = raw_assessment
        else:
            payload = vars(raw_assessment)

        # Extract primary metrics
        sha256 = payload.get("certificate_sha256", "")
        verdict = str(payload.get("verdict", "INCONCLUSIVE"))
        trust_score = payload.get("trust_score")
        if trust_score is None:
            trust_score = 0
        confidence = float(payload.get("confidence", 0.0))
        checks_completed = int(payload.get("checks_completed", 0))

        # Persist record in PostgreSQL / SQLite
        cert_scan = CertificateScan(
            id=uuid.uuid4(),
            user_id=user_id,
            target_hostname=target_host or payload.get("subject_dn") or "unknown",
            certificate_sha256=sha256,
            trust_score=trust_score,
            verdict=verdict,
            confidence=confidence,
            checks_completed=checks_completed,
            policy_evaluation=payload.get("policy_evaluation"),
            ml_advisory=payload.get("ml_advisory"),
            assessment_payload=payload,
            scanned_at=datetime.now(UTC),
        )
        db.add(cert_scan)
        await db.commit()
        await db.refresh(cert_scan)

        # Build response schema
        findings = [CertificateFindingItem.model_validate(f) for f in payload.get("findings", [])]

        return CertificateAssessmentResponse(
            id=cert_scan.id,
            target_hostname=target_host,
            certificate_sha256=sha256,
            subject_dn=payload.get("subject_dn", ""),
            issuer_dn=payload.get("issuer_dn", ""),
            verdict=verdict,
            trust_score=payload.get("trust_score"),
            confidence=confidence,
            scoring_version=payload.get("scoring_version", "cert_v1.0.0"),
            checks_completed=checks_completed,
            findings=findings,
            features=payload.get("features"),
            policy_evaluation=payload.get("policy_evaluation"),
            ml_advisory=payload.get("ml_advisory"),
            recommendations=payload.get("recommendations", []),
            summary=payload.get("summary", ""),
            evaluated_at=cert_scan.scanned_at,
        )

    async def get_certificate_scan(
        self,
        db: AsyncSession,
        scan_id: uuid.UUID,
        user_id: uuid.UUID | None = None,
        user_role: str = "USER",
    ) -> CertificateAssessmentResponse:
        """Fetch a specific certificate assessment by ID."""
        stmt = select(CertificateScan).where(CertificateScan.id == scan_id)
        result = await db.execute(stmt)
        cert_scan = result.scalars().first()

        if not cert_scan:
            raise EntityNotFoundException(f"Certificate assessment with ID {scan_id} not found.")

        # Permissions check: users can only see their own scans unless scan has no user or user is admin
        if user_role != "ADMIN" and cert_scan.user_id is not None:
            if user_id != cert_scan.user_id:
                raise EntityNotFoundException(
                    f"Certificate assessment with ID {scan_id} not found."
                )

        payload = cert_scan.assessment_payload
        findings = [CertificateFindingItem.model_validate(f) for f in payload.get("findings", [])]

        return CertificateAssessmentResponse(
            id=cert_scan.id,
            target_hostname=cert_scan.target_hostname,
            certificate_sha256=cert_scan.certificate_sha256,
            subject_dn=payload.get("subject_dn", ""),
            issuer_dn=payload.get("issuer_dn", ""),
            verdict=cert_scan.verdict,
            trust_score=payload.get("trust_score"),
            confidence=cert_scan.confidence,
            scoring_version=payload.get("scoring_version", "cert_v1.0.0"),
            checks_completed=cert_scan.checks_completed,
            findings=findings,
            features=payload.get("features"),
            policy_evaluation=cert_scan.policy_evaluation,
            ml_advisory=cert_scan.ml_advisory,
            recommendations=payload.get("recommendations", []),
            summary=payload.get("summary", ""),
            evaluated_at=cert_scan.scanned_at,
        )

    async def list_certificate_scans(
        self,
        db: AsyncSession,
        user_id: uuid.UUID | None = None,
        user_role: str = "USER",
        limit: int = 20,
        offset: int = 0,
    ) -> CertificateScanListResponse:
        """List previously evaluated certificate assessments."""
        limit = min(max(1, limit), 100)
        offset = max(0, offset)

        query = select(CertificateScan)
        count_query = select(func.count(CertificateScan.id))

        if user_role != "ADMIN" and user_id is not None:
            query = query.where(CertificateScan.user_id == user_id)
            count_query = count_query.where(CertificateScan.user_id == user_id)

        query = query.order_by(desc(CertificateScan.scanned_at)).offset(offset).limit(limit)

        total = (await db.execute(count_query)).scalar_one()
        records = (await db.execute(query)).scalars().all()

        items = [
            CertificateScanSummaryItem(
                id=rec.id,
                target_hostname=rec.target_hostname,
                certificate_sha256=rec.certificate_sha256,
                trust_score=rec.trust_score,
                verdict=rec.verdict,
                confidence=rec.confidence,
                checks_completed=rec.checks_completed,
                scanned_at=rec.scanned_at,
            )
            for rec in records
        ]

        return CertificateScanListResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )


certificate_service = CertificateService()
