"""User management endpoints."""

from fastapi import APIRouter, Depends, status

from app.core.permissions import get_current_user
from app.models.user import User
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current User",
    description="Retrieve account profile for the currently authenticated user.",
)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retrieve current user profile."""
    return UserResponse.model_validate(current_user)
