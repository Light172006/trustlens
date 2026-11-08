"""API endpoints for Web Security Posture Analysis."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user_optional
from app.database.session import get_db
from app.models.user import User
from app.schemas.web_security import (
    WebSecurityAnalyzeRequest,
    WebSecurityAssessmentResponse,
    WebSecurityScanListResponse,
)
from app.services.web_security_service import web_security_service

router = APIRouter()
alias_router = APIRouter()


@router.post(
    "/analyze",
    response_model=WebSecurityAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze website technical security posture",
    description=(
        "Executes safe passive telemetry extraction, evaluates deterministic security rules, "
        "runs calibrated ML posture classification with abstention, aggregates risk, "
        "and produces evidence-backed remediation guidance."
    ),
)
async def analyze_web_security(
    request: WebSecurityAnalyzeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User | None, Depends(get_current_user_optional)] = None,
) -> WebSecurityAssessmentResponse:
    """Analyze website technical security posture and persist scan result."""
    user_id = current_user.id if current_user else None
    return await web_security_service.analyze_url(
        db=db,
        request=request,
        user_id=user_id,
    )


@router.get(
    "/{id}",
    response_model=WebSecurityAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get web security scan by ID",
    description="Retrieve a previously executed web security assessment by its unique scan UUID.",
)
async def get_web_security_scan(
    id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> WebSecurityAssessmentResponse:
    """Fetch web security assessment details by scan ID."""
    return await web_security_service.get_scan_by_id(db=db, scan_id=id)


@router.get(
    "",
    response_model=WebSecurityScanListResponse,
    status_code=status.HTTP_200_OK,
    summary="List web security scans",
    description="Retrieve a paginated collection of historical web security scans with optional filtering.",
)
async def list_web_security_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    domain: Annotated[str | None, Query(description="Filter by target domain")] = None,
    posture: Annotated[
        str | None, Query(description="Filter by posture label (GOOD, MODERATE, POOR)")
    ] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 20,
    current_user: Annotated[User | None, Depends(get_current_user_optional)] = None,
) -> WebSecurityScanListResponse:
    """List web security scan records with optional domain/posture filtering."""
    # Filter by user if not admin, or view all if admin / public
    user_id = current_user.id if (current_user and current_user.role != "ADMIN") else None
    return await web_security_service.list_scans(
        db=db,
        user_id=user_id,
        domain=domain,
        posture=posture,
        page=page,
        limit=limit,
    )


# Alias route matching FINAL_BACKEND_HANDOFF.md Section 7: POST /api/v1/analyze/web-security
@alias_router.post(
    "/analyze/web-security",
    response_model=WebSecurityAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze website technical security posture (Handoff Alias)",
    description="Direct compatibility alias for POST /api/v1/web-security/analyze.",
)
async def analyze_web_security_alias(
    request: WebSecurityAnalyzeRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User | None, Depends(get_current_user_optional)] = None,
) -> WebSecurityAssessmentResponse:
    """Alias for POST /api/v1/web-security/analyze."""
    return await analyze_web_security(request=request, db=db, current_user=current_user)
