"""Role-based authorization and resource access control permissions."""

import uuid
from collections.abc import Callable
from enum import Enum
from typing import Any

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.security import decode_token
from app.database.session import get_db
from app.models.session import UserSession
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)


class Role(str, Enum):
    """User authorization roles."""

    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


async def get_current_token_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Validate Bearer token signature, expiry, and revocation state."""
    if not credentials or not credentials.credentials:
        raise AuthenticationError("A valid authenticated session is required.")
    raw_token = credentials.credentials
    payload = decode_token(raw_token)

    if payload.get("type") != "access":
        raise AuthenticationError("Invalid token type: Access token expected.")

    token_jti = payload.get("jti")
    if token_jti:
        stmt = select(UserSession).where(UserSession.token_jti == token_jti)
        result = await db.execute(stmt)
        session = result.scalar_one_or_none()
        if session and not session.is_active:
            raise AuthenticationError("Authentication session has been revoked.")

    return payload


async def get_current_user(
    payload: dict[str, Any] = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Retrieve currently authenticated user from token subject."""
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise AuthenticationError("Token lacks user identity.")

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise AuthenticationError("Invalid user identity in token.")

    user = await db.get(User, user_id)
    if user is None:
        raise AuthenticationError("User not found.")

    if user.account_status != "active":
        raise AuthorizationError("Account is suspended or deactivated.")

    return user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Retrieve authenticated user if valid token present, otherwise None."""
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            return None
        user_id_str = payload.get("sub")
        if not user_id_str:
            return None
        user = await db.get(User, uuid.UUID(user_id_str))
        if user and user.account_status == "active":
            return user
        return None
    except Exception:
        return None


async def require_moderator_or_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure authenticated user holds Moderator or Administrator role."""
    if current_user.role not in (Role.MODERATOR.value, Role.ADMIN.value):
        raise AuthorizationError("Moderator or Administrator privileges required.")
    return current_user


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure authenticated user holds Administrator role."""
    if current_user.role != Role.ADMIN.value:
        raise AuthorizationError("Administrator privileges required.")
    return current_user


def require_role(*allowed_roles: Role) -> Callable:
    """Factory dependency to enforce role constraints."""
    role_values = [r.value for r in allowed_roles]

    async def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in role_values:
            raise AuthorizationError("Insufficient permissions to access this resource.")
        return current_user

    return _role_checker


def verify_resource_ownership(
    resource_owner_id: Any, current_user_id: Any, current_user_role: str
) -> None:
    """Verify that current user is either the owner of the resource or an administrator."""
    if current_user_role == Role.ADMIN.value:
        return
    if str(resource_owner_id) != str(current_user_id):
        raise AuthorizationError("Access denied: You do not own this resource.")
