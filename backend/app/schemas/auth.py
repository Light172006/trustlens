"""Pydantic v2 schemas for authentication, credentials, and user data transfer."""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRole(str, Enum):
    """User authorization roles."""

    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class AccountStatus(str, Enum):
    """User account lifecycle status."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class RegisterRequest(BaseModel):
    """Payload for new user registration."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="Password meeting security criteria (minimum 12 characters)",
    )
    display_name: str = Field(
        ...,
        min_length=2,
        max_length=80,
        description="Display name for the user",
    )


class LoginRequest(BaseModel):
    """Payload for user authentication."""

    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="Account password")


class RefreshTokenRequest(BaseModel):
    """Payload for refreshing an expired access token."""

    refresh_token: str = Field(..., description="Valid JWT refresh token")


class TokenResponse(BaseModel):
    """JWT token response payload."""

    access_token: str = Field(..., description="JWT Bearer access token")
    refresh_token: str = Field(..., description="Rotated JWT refresh token")
    token_type: str = Field(default="bearer", description="Token scheme type")
    expires_in: int = Field(..., description="Access token lifetime in seconds")


class UserResponse(BaseModel):
    """Safe user profile representation excluding credential hashes."""

    id: uuid.UUID
    email: EmailStr
    display_name: str
    role: str
    account_status: str
    created_at: datetime
    last_login_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    """Composite response returning both user profile and authentication tokens."""

    user: UserResponse
    tokens: TokenResponse


class LogoutResponse(BaseModel):
    """Logout confirmation response."""

    logged_out: bool = Field(default=True, description="Confirmation that session was terminated")
