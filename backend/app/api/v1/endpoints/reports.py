"""Collaborative threat intelligence community reporting and voting endpoints."""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user, get_current_user_optional
from app.database.session import get_db
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.report import (
    CommunityReportCreateRequest,
    CommunityReportDetailResponse,
    CommunityReportSubmitResponse,
    CommunityVoteRequest,
    CommunityVoteResponse,
    PublicCommunityReportItem,
    UserCommunityReportItem,
)
from app.services.report_service import report_service

router = APIRouter(prefix="/community/reports", tags=["Community Reports"])


@router.post(
    "",
    response_model=CommunityReportSubmitResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Community Threat Report",
    description="Submits a suspicious URL and technical evidence for community moderation. Returns HTTP 201 or HTTP 200 if deduplicated within 30 days.",
)
async def submit_community_report(
    payload: CommunityReportCreateRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommunityReportSubmitResponse:
    """Submit a website for collaborative threat intelligence review."""
    result = await report_service.submit_report(
        db=db,
        user_id=current_user.id,
        payload=payload,
    )
    if result.duplicate_submission:
        response.status_code = status.HTTP_200_OK

    return result


@router.get(
    "",
    response_model=PaginatedResponse[PublicCommunityReportItem],
    status_code=status.HTTP_200_OK,
    summary="List Confirmed Community Reports",
    description="Returns public, moderator-confirmed community threat intelligence reports with confirmation and false-positive vote counts.",
)
async def list_confirmed_reports(
    category: str | None = Query(default=None, description="Filter by threat category"),
    host: str | None = Query(default=None, description="Filter by hostname substring"),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[PublicCommunityReportItem]:
    """Retrieve public list of confirmed threat reports."""
    items, total = await report_service.list_public_reports(
        db=db,
        category=category,
        host=host,
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


@router.get(
    "/mine",
    response_model=PaginatedResponse[UserCommunityReportItem],
    status_code=status.HTTP_200_OK,
    summary="List My Community Submissions",
    description="Returns private list of community reports submitted by the authenticated user across all moderation states.",
)
async def list_my_reports(
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by report status (pending, confirmed, rejected, duplicate)",
    ),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[UserCommunityReportItem]:
    """Retrieve personal submissions for the current authenticated user."""
    items, total = await report_service.list_user_reports(
        db=db,
        user_id=current_user.id,
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


@router.get(
    "/{report_id}",
    response_model=CommunityReportDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Community Report Detail",
    description="Fetches community report details. Public users may only view confirmed reports; reporters and moderators may view in any status.",
)
async def get_report_detail(
    report_id: uuid.UUID,
    optional_user: User | None = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
) -> CommunityReportDetailResponse:
    """Retrieve full details of a single community threat report."""
    user_id = optional_user.id if optional_user else None
    user_role = optional_user.role if optional_user else None
    return await report_service.get_report_detail(
        db=db,
        report_id=report_id,
        current_user_id=user_id,
        current_user_role=user_role,
    )


@router.post(
    "/{report_id}/votes",
    response_model=CommunityVoteResponse,
    status_code=status.HTTP_200_OK,
    summary="Cast or Update Community Vote",
    description="Endorse (confirm) or dispute (false_positive) a confirmed community threat report. Users cannot vote on their own reports.",
)
async def cast_community_vote(
    report_id: uuid.UUID,
    payload: CommunityVoteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> CommunityVoteResponse:
    """Submit confirmation or false-positive vote for a confirmed report."""
    return await report_service.cast_vote(
        db=db,
        user_id=current_user.id,
        report_id=report_id,
        payload=payload,
    )
