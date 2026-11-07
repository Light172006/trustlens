"""Scan endpoints for URL submission, status tracking, report inspection, and findings."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.scan import (
    CertificateDetailResponse,
    ScanCreateRequest,
    ScanDetailResponse,
    ScanFindingsResponse,
    ScanRecordResponse,
    ScanSubmitResponse,
    ScanSummaryItem,
)
from app.services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "",
    response_model=ScanSubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit Website for Security Scan",
    description="Submits a public URL for asynchronous security analysis. Returns HTTP 202 or HTTP 200 if deduplicated within 60s.",
)
async def submit_scan(
    payload: ScanCreateRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanSubmitResponse:
    """Submit a URL for scanning."""
    scan, deduplicated = await scan_service.create_scan(
        db=db,
        user_id=current_user.id,
        payload=payload,
    )
    if deduplicated:
        response.status_code = status.HTTP_200_OK

    return ScanSubmitResponse(
        scan=ScanRecordResponse.model_validate(scan),
        deduplicated=deduplicated,
    )


@router.get(
    "",
    response_model=PaginatedResponse[ScanSummaryItem],
    status_code=status.HTTP_200_OK,
    summary="List User Scans",
    description="Returns paginated scan history scoped strictly to the authenticated user.",
)
async def list_scans(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: str | None = Query(
        default=None, description="Filter by status (queued, running, succeeded, partial, failed)"
    ),
    verdict: str | None = Query(
        default=None, description="Filter by verdict (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)"
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[ScanSummaryItem]:
    """List authenticated user scans."""
    items, total = await scan_service.list_scans(
        db=db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        status_filter=status,
        verdict_filter=verdict,
    )
    return PaginatedResponse[ScanSummaryItem](
        items=items,
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scan Report",
    description="Retrieves comprehensive scan assessment, findings, coverage, provider checks, and redirects.",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    """Fetch scan report."""
    return await scan_service.get_scan_detail(
        db=db,
        user_id=current_user.id,
        user_role=current_user.role,
        scan_id=scan_id,
    )


@router.get(
    "/{scan_id}/findings",
    response_model=ScanFindingsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scan Findings",
    description="Lists all technical findings and security observations discovered during the scan.",
)
async def get_scan_findings(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanFindingsResponse:
    """Fetch scan findings."""
    findings = await scan_service.get_scan_findings(
        db=db,
        user_id=current_user.id,
        user_role=current_user.role,
        scan_id=scan_id,
    )
    return ScanFindingsResponse(
        scan_id=scan_id,
        items=findings,
        total=len(findings),
    )


@router.get(
    "/{scan_id}/certificate",
    response_model=CertificateDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Scan Certificate Details",
    description="Returns leaf certificate details for HTTPS targets, or availability reason if not HTTPS / failed.",
)
async def get_scan_certificate(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CertificateDetailResponse:
    """Fetch scan certificate details."""
    return await scan_service.get_scan_certificate(
        db=db,
        user_id=current_user.id,
        user_role=current_user.role,
        scan_id=scan_id,
    )


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Scan Record",
    description="Deletes an owned scan record and cascading child relations.",
)
async def delete_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete scan."""
    await scan_service.delete_scan(
        db=db,
        user_id=current_user.id,
        user_role=current_user.role,
        scan_id=scan_id,
    )
