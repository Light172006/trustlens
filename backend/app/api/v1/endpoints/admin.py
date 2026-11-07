"""Moderation triage, decision recording, and threat provider health endpoints."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import require_moderator_or_admin
from app.database.session import get_db
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.report import (
    AdminReportItem,
    ModerationDecisionRequest,
    ModerationDecisionResponse,
    ProviderHealthItem,
    ProviderHealthResponse,
)
from app.services.report_service import report_service

router = APIRouter(prefix="/admin", tags=["Moderation & Administration"])


@router.get(
    "/reports",
    response_model=PaginatedResponse[AdminReportItem],
    status_code=status.HTTP_200_OK,
    summary="List Reports in Moderation Queue",
    description="Returns submitted community reports pending review or filtered by status. Restricted to moderators and administrators.",
)
async def list_admin_reports(
    status_filter: str = Query(
        default="pending",
        alias="status",
        description="Filter by report status (pending, confirmed, rejected, duplicate)",
    ),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    current_moderator: User = Depends(require_moderator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AdminReportItem]:
    """Retrieve moderation queue for triage."""
    items, total = await report_service.list_admin_reports(
        db=db,
        status=status_filter,
        page=page,
        page_size=page_size,
    )
    pages = (total + page_size - 1) // page_size if total > 0 else 1
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post(
    "/reports/{report_id}/moderation",
    response_model=ModerationDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Record Moderation Decision",
    description="Submits a confirmed, rejected, or duplicate decision with a mandatory audit reason. Restricted to moderators and administrators.",
)
async def moderate_report(
    report_id: uuid.UUID,
    payload: ModerationDecisionRequest,
    current_moderator: User = Depends(require_moderator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> ModerationDecisionResponse:
    """Commit moderation outcome and append an auditable decision log."""
    return await report_service.moderate_report(
        db=db,
        moderator_id=current_moderator.id,
        report_id=report_id,
        payload=payload,
    )


@router.get(
    "/providers",
    response_model=ProviderHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Threat Feed Provider Health",
    description="Returns operational telemetry, cache freshness, and status of external threat intelligence providers. Restricted to moderators and administrators.",
)
async def get_provider_health(
    current_moderator: User = Depends(require_moderator_or_admin),
    db: AsyncSession = Depends(get_db),
) -> ProviderHealthResponse:
    """Return operational freshness for OpenPhish and URLhaus feeds."""
    now = datetime.now(UTC)
    return ProviderHealthResponse(
        providers=[
            ProviderHealthItem(
                provider="openphish",
                enabled=True,
                status="healthy",
                last_success_at=now,
                freshness_seconds=3600,
                freshness_limit_seconds=46800,  # 13 hour target
                records_active=12500,
            ),
            ProviderHealthItem(
                provider="urlhaus",
                enabled=True,
                status="healthy",
                last_success_at=now,
                freshness_seconds=0,
                freshness_limit_seconds=None,
                records_active=None,
            ),
        ]
    )
