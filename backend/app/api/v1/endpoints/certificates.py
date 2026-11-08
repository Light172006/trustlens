"""Direct Certificate Analyzer API endpoints."""

import socket
import ssl
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    ConflictError,
    TargetNotPublicException,
    TrustLensException,
)
from app.core.logging import logger
from app.core.permissions import get_current_user_optional
from app.database.session import get_db
from app.models.certificate import CertificateScan
from app.models.user import User
from app.scanners.url_validator import resolve_hostname_ips
from app.schemas.certificate import (
    CertificateAnalyzeRequest,
    CertificateAssessmentResponse,
)

router = APIRouter(prefix="/certificates", tags=["Certificate Intelligence"])


@router.post(
    "/analyze",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Analyze Certificate or Endpoint TLS",
    description=(
        "Evaluates X.509 leaf/bundle certificates or performs an active TLS handshake "
        "to deliver RFC 9525, RFC 5280, RFC 6962, CA/B Forum v2.3.1 compliance, "
        "and deterministic Trust Scores."
    ),
)
async def analyze_certificate_endpoint(
    payload: CertificateAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
) -> dict[str, Any]:
    """Execute direct cryptographic and trust evaluation."""
    if not payload.hostname and not payload.pem:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Either 'hostname' or 'pem' must be provided for certificate evaluation.",
        )

    # 1. Evaluate PEM bundle or single PEM certificate if provided
    if payload.pem:
        pem_str = payload.pem.strip()
        if len(pem_str.encode("utf-8")) > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Certificate payload exceeds the 10 MB maximum size limit.",
            )

        try:
            from certificate_analyzer.api import analyze_pem

            assessment = analyze_pem(
                pem_str=pem_str,
                target_hostname=payload.hostname,
                reference_time=datetime.now(UTC),
                include_ml_advisory=payload.include_ml_advisory,
            )
            assessment_dict = assessment.model_dump(mode="json")

            # Persist scan audit record
            cert_scan = CertificateScan(
                id=uuid.uuid4(),
                target_hostname=payload.hostname or assessment_dict.get("subject_dn", "UNKNOWN"),
                certificate_sha256=assessment_dict["certificate_sha256"],
                trust_score=assessment_dict["trust_score"],
                verdict=assessment_dict["verdict"],
                confidence=assessment_dict["confidence"],
                checks_completed=assessment_dict.get("checks_completed", 6),
                policy_evaluation=assessment_dict.get("policy_evaluation"),
                ml_advisory=assessment_dict.get("ml_advisory"),
                assessment_payload=assessment_dict,
                scanned_at=datetime.now(UTC),
            )
            db.add(cert_scan)
            await db.commit()

            return assessment_dict

        except Exception as exc:
            logger.exception(f"Error evaluating PEM certificate: {exc}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Certificate analysis failed: {str(exc)}",
            )

    # 2. Hostname-based TLS Endpoint Analysis
    hostname = payload.hostname.strip().lower()
    port = payload.port or 443

    # SSRF Protection: verify destination hostname/IP resolves exclusively to public IPs
    import ipaddress
    from app.scanners.url_validator import is_ip_globally_routable

    try:
        direct_ip = ipaddress.ip_address(hostname)
        resolved_ips = [str(direct_ip)]
    except ValueError:
        resolved_ips = resolve_hostname_ips(hostname)

    if not resolved_ips:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not resolve hostname '{hostname}' via DNS.",
        )

    for ip_str in resolved_ips:
        if not is_ip_globally_routable(ip_str):
            raise TargetNotPublicException(
                message=f"SSRF Protection: Hostname resolves to private/internal IP {ip_str}.",
                issue=f"IP address {ip_str} is private, loopback, or non-public.",
            )

    # Perform active TLS handshake to retrieve peer certificate
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Collect raw bytes even if invalid to audit failure

    target_ip = resolved_ips[0]
    leaf_der: bytes | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None

    try:
        with socket.create_connection((target_ip, port), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                leaf_der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                cipher_suite = cipher_info[0] if cipher_info else None
    except Exception as exc:
        logger.debug(f"TLS connection to {hostname}:{port} failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"TLS handshake with {hostname}:{port} failed: {type(exc).__name__}",
        )

    if not leaf_der:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"TLS server at {hostname}:{port} did not provide a parseable leaf certificate.",
        )

    try:
        from certificate_analyzer.api import analyze_endpoint_tls

        assessment = analyze_endpoint_tls(
            certificate_der=leaf_der,
            target_hostname=hostname,
            port=port,
            tls_protocol_version=tls_version or "TLSv1.3",
            cipher_suite=cipher_suite,
            reference_time=datetime.now(UTC),
            include_ml_advisory=payload.include_ml_advisory,
        )
        assessment_dict = assessment.model_dump(mode="json")

        # Persist audit record
        cert_scan = CertificateScan(
            id=uuid.uuid4(),
            target_hostname=hostname,
            certificate_sha256=assessment_dict["certificate_sha256"],
            trust_score=assessment_dict["trust_score"],
            verdict=assessment_dict["verdict"],
            confidence=assessment_dict["confidence"],
            checks_completed=assessment_dict.get("checks_completed", 6),
            policy_evaluation=assessment_dict.get("policy_evaluation"),
            ml_advisory=assessment_dict.get("ml_advisory"),
            assessment_payload=assessment_dict,
            scanned_at=datetime.now(UTC),
        )
        db.add(cert_scan)
        await db.commit()

        return assessment_dict

    except Exception as exc:
        logger.exception(f"Certificate analysis failed for endpoint {hostname}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Certificate Analyzer internal error: {str(exc)}",
        )
