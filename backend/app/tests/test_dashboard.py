"""Automated tests for user dashboard summary, verdict distribution, and recent scans."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan


@pytest.fixture
async def dashboard_user(client: AsyncClient) -> dict:
    """Create a registered user for dashboard tests."""
    payload = {
        "email": f"dash.{uuid.uuid4().hex[:8]}@example.com",
        "password": "DashPassword123!",
        "display_name": "Dashboard Tester",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    token = resp.json()["tokens"]["access_token"]
    user_id = resp.json()["user"]["id"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": uuid.UUID(user_id),
    }


@pytest.fixture
async def other_user(client: AsyncClient) -> dict:
    """Create another user to verify dashboard isolation."""
    payload = {
        "email": f"dash.other.{uuid.uuid4().hex[:8]}@example.com",
        "password": "OtherPassword123!",
        "display_name": "Other Tester",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    token = resp.json()["tokens"]["access_token"]
    user_id = resp.json()["user"]["id"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": uuid.UUID(user_id),
    }


@pytest.mark.asyncio
async def test_dashboard_empty_for_new_user(
    client: AsyncClient,
    dashboard_user: dict,
) -> None:
    """Verify newly registered user sees zeroed metrics and empty recent scans."""
    resp = await client.get("/api/v1/dashboard/summary", headers=dashboard_user["headers"])
    assert resp.status_code == 200

    data = resp.json()
    summary = data["summary"]
    assert summary["total_scans"] == 0
    assert summary["scans_last_30_days"] == 0
    assert summary["active_scans"] == 0
    assert summary["pending_community_reports"] == 0
    assert summary["verdict_counts"] == {
        "SAFE": 0,
        "SUSPICIOUS": 0,
        "MALICIOUS": 0,
        "INCONCLUSIVE": 0,
    }
    assert len(data["recent_scans"]) == 0


@pytest.mark.asyncio
async def test_dashboard_populated_with_scans_and_verdicts(
    client: AsyncClient,
    db_session: AsyncSession,
    dashboard_user: dict,
) -> None:
    """Verify summary correctly tallies total scans, active scans, and verdict distribution."""
    user_id = dashboard_user["user_id"]

    # Seed 3 scans directly for dashboard_user
    scan1 = Scan(
        id=uuid.uuid4(),
        user_id=user_id,
        original_url="https://example1.com",
        canonical_url="https://example1.com",
        host="example1.com",
        scheme="https",
        status="succeeded",
        verdict="SAFE",
        risk_score=10,
        scoring_version="trustlens-1.0",
        checks_completed=4,
    )
    scan2 = Scan(
        id=uuid.uuid4(),
        user_id=user_id,
        original_url="https://example2.com",
        canonical_url="https://example2.com",
        host="example2.com",
        scheme="https",
        status="succeeded",
        verdict="MALICIOUS",
        risk_score=95,
        scoring_version="trustlens-1.0",
        checks_completed=4,
    )
    scan3 = Scan(
        id=uuid.uuid4(),
        user_id=user_id,
        original_url="https://example3.com",
        canonical_url="https://example3.com",
        host="example3.com",
        scheme="https",
        status="running",
        verdict="INCONCLUSIVE",
        scoring_version="trustlens-1.0",
        checks_completed=1,
    )
    db_session.add_all([scan1, scan2, scan3])
    await db_session.commit()

    resp = await client.get("/api/v1/dashboard/summary", headers=dashboard_user["headers"])
    assert resp.status_code == 200

    data = resp.json()
    summary = data["summary"]
    assert summary["total_scans"] == 3
    assert summary["scans_last_30_days"] == 3
    assert summary["active_scans"] == 1  # scan3 is running
    assert summary["verdict_counts"]["SAFE"] == 1
    assert summary["verdict_counts"]["MALICIOUS"] == 1
    assert summary["verdict_counts"]["INCONCLUSIVE"] == 1
    assert summary["verdict_counts"]["SUSPICIOUS"] == 0

    assert len(data["recent_scans"]) == 3
    # Ordered created_at desc
    hosts = [s["host"] for s in data["recent_scans"]]
    assert "example1.com" in hosts
    assert "example2.com" in hosts
    assert "example3.com" in hosts


@pytest.mark.asyncio
async def test_dashboard_user_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
    dashboard_user: dict,
    other_user: dict,
) -> None:
    """Verify user dashboard metrics do not leak or count other users' scans."""
    # Seed scan owned by dashboard_user
    scan = Scan(
        id=uuid.uuid4(),
        user_id=dashboard_user["user_id"],
        original_url="https://private-user.com",
        canonical_url="https://private-user.com",
        host="private-user.com",
        scheme="https",
        status="succeeded",
        verdict="MALICIOUS",
        risk_score=90,
        scoring_version="trustlens-1.0",
        checks_completed=4,
    )
    db_session.add(scan)
    await db_session.commit()

    # other_user queries dashboard -> must see 0 scans
    resp = await client.get("/api/v1/dashboard/summary", headers=other_user["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["total_scans"] == 0
    assert len(data["recent_scans"]) == 0


@pytest.mark.asyncio
async def test_dashboard_unauthenticated_rejected(client: AsyncClient) -> None:
    """Verify unauthenticated request to dashboard summary returns HTTP 401."""
    resp = await client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
