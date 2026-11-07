"""Domain service for user registration, authentication, token rotation, and sessions."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AuthenticationError, AuthorizationError, ConflictError
from app.core.rate_limit import enforce_rate_limit
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.session import UserSession
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse


class AuthService:
    """Manages user authentication lifecycle and cryptographic token issuance."""

    async def register_user(
        self,
        db: AsyncSession,
        payload: RegisterRequest,
    ) -> tuple[User, TokenResponse]:
        """Register a new user account and issue an initial token pair."""
        normalized_email = str(payload.email).lower().strip()

        # Check existing user
        stmt = select(User).where(User.email == normalized_email)
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is not None:
            raise ConflictError(
                message="An account with this email address already exists.",
                field="email",
                issue="Already registered",
            )

        # Hash credentials with Argon2id
        hashed_pw = hash_password(payload.password)

        new_user = User(
            id=uuid.uuid4(),
            email=normalized_email,
            password_hash=hashed_pw,
            display_name=payload.display_name.strip(),
            role="user",
            account_status="active",
            last_login_at=datetime.now(UTC),
        )
        db.add(new_user)
        await db.flush()

        # Issue tokens
        tokens = await self._issue_token_pair(db, new_user)
        await db.commit()
        await db.refresh(new_user)

        return new_user, tokens

    async def authenticate_user(
        self,
        db: AsyncSession,
        payload: LoginRequest,
        client_ip: str = "unknown",
    ) -> tuple[User, TokenResponse]:
        """Authenticate user credentials and issue rotated tokens with rate limiting."""
        normalized_email = str(payload.email).lower().strip()

        # Enforce rate limit (5 attempts per minute per email/IP)
        rate_key = f"auth_login:{client_ip}:{normalized_email}"
        await enforce_rate_limit(
            key=rate_key,
            max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE,
            window_seconds=60,
        )

        stmt = select(User).where(User.email == normalized_email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None or not verify_password(payload.password, user.password_hash):
            raise AuthenticationError("Invalid email or password.")

        if user.account_status != "active":
            raise AuthorizationError("Account is suspended or inactive.")

        user.last_login_at = datetime.now(UTC)
        tokens = await self._issue_token_pair(db, user)
        await db.commit()
        await db.refresh(user)

        return user, tokens

    async def refresh_tokens(
        self,
        db: AsyncSession,
        refresh_token_str: str,
    ) -> tuple[User, TokenResponse]:
        """Validate refresh token, rotate tokens, and revoke the previous refresh token."""
        payload = decode_token(refresh_token_str)
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type: refresh token expected.")

        token_jti = payload.get("jti")
        user_id_str = payload.get("sub")
        if not token_jti or not user_id_str:
            raise AuthenticationError("Malformed refresh token payload.")

        try:
            user_id = uuid.UUID(user_id_str)
        except ValueError:
            raise AuthenticationError("Invalid user identity in token.")

        # Check if session exists and is active
        stmt = select(UserSession).where(UserSession.refresh_token_jti == token_jti)
        result = await db.execute(stmt)
        active_session = result.scalar_one_or_none()

        if active_session is None or not active_session.is_active:
            raise AuthenticationError("Refresh token has been revoked or expired.")

        # Revoke old session as part of refresh rotation
        active_session.revoked_at = datetime.now(UTC)
        active_session.revoke_reason = "rotated"

        # Fetch user
        user = await db.get(User, user_id)
        if user is None or user.account_status != "active":
            raise AuthorizationError("Account is inactive or not found.")

        # Issue fresh token pair
        tokens = await self._issue_token_pair(db, user)
        await db.commit()

        return user, tokens

    async def revoke_token(
        self,
        db: AsyncSession,
        token_payload: dict,
        reason: str = "logout",
    ) -> None:
        """Revoke active user sessions matching the given token."""
        token_jti = token_payload.get("jti")
        if not token_jti:
            return

        stmt = select(UserSession).where(
            (UserSession.token_jti == token_jti) | (UserSession.refresh_token_jti == token_jti)
        )
        result = await db.execute(stmt)
        sessions = result.scalars().all()
        now = datetime.now(UTC)
        for s in sessions:
            if s.is_active:
                s.revoked_at = now
                s.revoke_reason = reason

        await db.commit()

    async def _issue_token_pair(self, db: AsyncSession, user: User) -> TokenResponse:
        """Issue an access and refresh token pair and persist the session record."""
        access_token = create_access_token(
            subject=str(user.id),
            email=user.email,
            role=user.role,
        )
        refresh_token = create_refresh_token(
            subject=str(user.id),
        )

        access_payload = decode_token(access_token)
        refresh_payload = decode_token(refresh_token)

        access_jti = access_payload["jti"]
        refresh_jti = refresh_payload["jti"]
        expires_at = datetime.fromtimestamp(access_payload["exp"], tz=UTC)

        session_record = UserSession(
            id=uuid.uuid4(),
            user_id=user.id,
            token_jti=access_jti,
            refresh_token_jti=refresh_jti,
            expires_at=expires_at,
        )
        db.add(session_record)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )


auth_service = AuthService()
