"""REST API endpoints for Certificate Security Analysis and Assessment Queries."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.certificate import (
    CertificateAnalyzeRequest,
    CertificateAssessmentResponse,
    CertificateScanListResponse,
)
from app.services.certificate_service import certificate_service

router = APIRouter()


@router.post(
    "/analyze",
    response_model=CertificateAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Certificate or Endpoint TLS",
    description=(
        "Executes authoritative digital trust evaluation on an X.509 certificate supplied "
        "as raw DER (base64), PEM bundle string, or active TLS endpoint hostname. Returns "
        "deterministic Trust Score (0-100), CA/B Forum policy evaluation, RFC 9525 hostname "
        "verification, and optional ML compliance advisory."
    ),
)
async def analyze_certificate(
    request: CertificateAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CertificateAssessmentResponse:
    """Analyze a certificate and persist the assessment record."""
    return await certificate_service.analyze_certificate_request(
        db=db,
        request=request,
        user_id=current_user.id,
    )


@router.get(
    "/{certificate_scan_id}",
    response_model=CertificateAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Certificate Assessment Details",
    description="Retrieves a full certificate assessment record by its unique ID.",
)
async def get_certificate_assessment(
    certificate_scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CertificateAssessmentResponse:
    """Fetch stored certificate assessment."""
    return await certificate_service.get_certificate_scan(
        db=db,
        scan_id=certificate_scan_id,
        user_id=current_user.id,
        user_role=current_user.role,
    )


@router.get(
    "",
    response_model=CertificateScanListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Certificate Assessments",
    description="Lists previous certificate evaluations performed by the authenticated user.",
)
async def list_certificate_assessments(
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CertificateScanListResponse:
    """List paginated certificate assessments."""
    return await certificate_service.list_certificate_scans(
        db=db,
        user_id=current_user.id,
        user_role=current_user.role,
        limit=limit,
        offset=offset,
    )
