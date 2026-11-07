"""Authentication endpoints for user registration, login, token rotation, and logout."""

from typing import Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_token_payload, get_current_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import (
    AuthResponse,
    LoginRequest,
    LogoutResponse,
    RefreshTokenRequest,
    RegisterRequest,
    UserResponse,
)
from app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user with Argon2id password hashing and issues initial JWT tokens.",
)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Create user account and return JWT credentials."""
    user, tokens = await auth_service.register_user(db=db, payload=payload)
    return AuthResponse(
        user=UserResponse.model_validate(user),
        tokens=tokens,
    )


@router.post(
    "/login",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login",
    description="Authenticates credentials and returns a rotated token pair with brute-force rate limiting.",
)
async def login(
    request: Request,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Authenticate email and password and issue tokens."""
    client_ip = request.client.host if request.client else "unknown"
    user, tokens = await auth_service.authenticate_user(
        db=db,
        payload=payload,
        client_ip=client_ip,
    )
    return AuthResponse(
        user=UserResponse.model_validate(user),
        tokens=tokens,
    )


@router.post(
    "/refresh",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh Access Token",
    description="Rotates refresh tokens, invalidates previous refresh token, and issues a fresh token pair.",
)
async def refresh_token(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Rotate JWT refresh token."""
    user, tokens = await auth_service.refresh_tokens(
        db=db,
        refresh_token_str=payload.refresh_token,
    )
    return AuthResponse(
        user=UserResponse.model_validate(user),
        tokens=tokens,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout User Session",
    description="Revokes current active session and invalidates access/refresh tokens.",
)
async def logout(
    token_payload: dict[str, Any] = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> LogoutResponse:
    """Revoke user session."""
    await auth_service.revoke_token(db=db, token_payload=token_payload, reason="logout")
    return LogoutResponse(logged_out=True)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current User Profile",
    description="Returns current authenticated user identity and role.",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retrieve profile of authenticated caller."""
    return UserResponse.model_validate(current_user)
