"""Dashboard endpoints for user security metrics and activity overview."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.dashboard import DashboardSummaryResponse
from app.services.dashboard_service import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="User Dashboard Summary",
    description="Returns aggregate scan statistics, verdict distributions, active scans, and the 10 most recent scans strictly scoped to the authenticated user.",
)
async def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardSummaryResponse:
    """Fetch user-scoped security scan summary and recent scans."""
    return await dashboard_service.get_dashboard_summary(
        db=db,
        user_id=current_user.id,
    )

