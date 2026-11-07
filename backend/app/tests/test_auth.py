"""Automated test suite for authentication, authorization, and session management."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(client: AsyncClient) -> None:
    """Verify new user registration with Argon2id password hashing and initial tokens."""
    payload = {
        "email": "security.analyst@example.com",
        "password": "SecurePassword123!",
        "display_name": "Security Analyst",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert "user" in data
    assert "tokens" in data

    user = data["user"]
    assert user["email"] == "security.analyst@example.com"
    assert user["display_name"] == "Security Analyst"
    assert user["role"] == "user"
    assert user["account_status"] == "active"
    assert "password" not in user
    assert "password_hash" not in user

    tokens = data["tokens"]
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] > 0


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(client: AsyncClient) -> None:
    """Verify registration rejects duplicate email addresses with HTTP 409."""
    payload = {
        "email": "duplicate@example.com",
        "password": "SecurePassword123!",
        "display_name": "First User",
    }
    resp1 = await client.post("/api/v1/auth/register", json=payload)
    assert resp1.status_code == 201

    # Attempt second registration with same email
    resp2 = await client.post("/api/v1/auth/register", json=payload)
    assert resp2.status_code == 409
    data = resp2.json()
    assert data["error"]["code"] == "STATE_CONFLICT"


@pytest.mark.asyncio
async def test_register_short_password_rejected(client: AsyncClient) -> None:
    """Verify password length security requirement (minimum 12 characters)."""
    payload = {
        "email": "weak@example.com",
        "password": "short",
        "display_name": "Weak Pass User",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient) -> None:
    """Verify successful login returns valid JWT token pair."""
    reg_payload = {
        "email": "login.test@example.com",
        "password": "ValidPassword123!",
        "display_name": "Login Tester",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_resp.status_code == 201

    login_payload = {
        "email": "login.test@example.com",
        "password": "ValidPassword123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200

    data = response.json()
    assert data["user"]["email"] == "login.test@example.com"
    assert "access_token" in data["tokens"]
    assert "refresh_token" in data["tokens"]


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient) -> None:
    """Verify invalid password returns 401 and generic error message."""
    reg_payload = {
        "email": "auth.fail@example.com",
        "password": "ValidPassword123!",
        "display_name": "Fail Tester",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "email": "auth.fail@example.com",
        "password": "WrongPassword123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient) -> None:
    """Verify login with non-existent email returns 401 without revealing account absence."""
    login_payload = {
        "email": "ghost.user@example.com",
        "password": "AnyPassword123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_refresh_token_rotation_and_revocation(client: AsyncClient) -> None:
    """Verify refresh token rotation and that previously used refresh tokens are invalidated."""
    reg_payload = {
        "email": "rotate.token@example.com",
        "password": "RotatePassword123!",
        "display_name": "Token Rotator",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    initial_refresh_token = reg_resp.json()["tokens"]["refresh_token"]

    # First refresh: must succeed
    refresh_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert refresh_resp.status_code == 200
    rotated_tokens = refresh_resp.json()["tokens"]
    new_access_token = rotated_tokens["access_token"]
    new_refresh_token = rotated_tokens["refresh_token"]
    assert new_access_token != ""
    assert new_refresh_token != initial_refresh_token

    # Re-using the initial (now rotated) refresh token must fail
    replay_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": initial_refresh_token},
    )
    assert replay_resp.status_code == 401
    assert replay_resp.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_logout_revokes_token(client: AsyncClient) -> None:
    """Verify logout revokes active session and blocks subsequent authenticated requests."""
    reg_payload = {
        "email": "logout.user@example.com",
        "password": "LogoutPassword123!",
        "display_name": "Logout User",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    access_token = reg_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # Verify access to /me before logout
    me_resp_before = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp_before.status_code == 200

    # Call logout
    logout_resp = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout_resp.status_code == 200
    assert logout_resp.json()["logged_out"] is True

    # Subsequent access using revoked token must be rejected
    me_resp_after = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp_after.status_code == 401
    assert me_resp_after.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_get_me_endpoints(client: AsyncClient) -> None:
    """Verify authenticated user can retrieve profile via /auth/me and /users/me."""
    reg_payload = {
        "email": "profile.check@example.com",
        "password": "ProfilePassword123!",
        "display_name": "Profile Owner",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    access_token = reg_resp.json()["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    resp1 = await client.get("/api/v1/auth/me", headers=headers)
    assert resp1.status_code == 200
    assert resp1.json()["email"] == "profile.check@example.com"

    resp2 = await client.get("/api/v1/users/me", headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["display_name"] == "Profile Owner"


@pytest.mark.asyncio
async def test_unauthorized_access_rejected(client: AsyncClient) -> None:
    """Verify endpoints reject unauthenticated requests with HTTP 401."""
    resp_no_auth = await client.get("/api/v1/auth/me")
    assert resp_no_auth.status_code == 401

    resp_bad_token = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.fake.token"},
    )
    assert resp_bad_token.status_code == 401
