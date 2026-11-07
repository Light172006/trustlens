"""Automated tests for collaborative threat intelligence community reports, votes, and moderation."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditEvent
from app.models.report import CommunityReport
from app.models.user import User
from app.scanners import url_validator


@pytest.fixture(autouse=True)
def mock_dns_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure instant DNS resolution for example domains in tests."""
    original_resolve = url_validator.resolve_hostname_ips

    def _mock_resolve(hostname: str) -> list[str]:
        if "example.com" in hostname or "phishing.test" in hostname or "malware.test" in hostname:
            return ["93.184.216.34"]
        return original_resolve(hostname)

    monkeypatch.setattr(url_validator, "resolve_hostname_ips", _mock_resolve)


@pytest.fixture
async def regular_reporter(client: AsyncClient) -> dict:
    """Create a standard registered user as reporter."""
    payload = {
        "email": f"reporter.{uuid.uuid4().hex[:8]}@example.com",
        "password": "ReportPassword123!",
        "display_name": "Reporter One",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    return {
        "headers": {"Authorization": f"Bearer {resp.json()['tokens']['access_token']}"},
        "user_id": uuid.UUID(resp.json()["user"]["id"]),
        "email": payload["email"],
    }


@pytest.fixture
async def community_voter(client: AsyncClient) -> dict:
    """Create a distinct user to vote on reports."""
    payload = {
        "email": f"voter.{uuid.uuid4().hex[:8]}@example.com",
        "password": "VoterPassword123!",
        "display_name": "Community Voter",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    return {
        "headers": {"Authorization": f"Bearer {resp.json()['tokens']['access_token']}"},
        "user_id": uuid.UUID(resp.json()["user"]["id"]),
    }


@pytest.fixture
async def moderator_user(client: AsyncClient, db_session: AsyncSession) -> dict:
    """Create a user with moderator role."""
    payload = {
        "email": f"mod.{uuid.uuid4().hex[:8]}@example.com",
        "password": "ModPassword123!",
        "display_name": "TrustLens Moderator",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    user_id = uuid.UUID(resp.json()["user"]["id"])

    # Promote to moderator in database
    user = await db_session.get(User, user_id)
    assert user is not None
    user.role = "moderator"
    await db_session.commit()

    # Re-login to receive token with moderator role
    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": payload["email"], "password": payload["password"]}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["tokens"]["access_token"]

    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": user_id,
    }


@pytest.mark.asyncio
async def test_submit_valid_community_report_returns_201(
    client: AsyncClient,
    regular_reporter: dict,
) -> None:
    """Verify submitting a valid suspicious URL creates a report with pending status."""
    payload = {
        "url": "https://phishing.test/login",
        "category": "phishing",
        "claimed_verdict": "MALICIOUS",
        "evidence_text": "This website mimics a popular banking sign-in portal and harvests login credentials.",
    }
    resp = await client.post(
        "/api/v1/community/reports",
        json=payload,
        headers=regular_reporter["headers"],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["duplicate_submission"] is False
    assert data["report"]["status"] == "pending"
    assert data["report"]["category"] == "phishing"
    assert data["report"]["claimed_verdict"] == "MALICIOUS"
    assert data["report"]["host"] == "phishing.test"


@pytest.mark.asyncio
async def test_submit_duplicate_report_within_30_days_returns_200(
    client: AsyncClient,
    regular_reporter: dict,
) -> None:
    """Verify submitting identical canonical URL within 30 days returns existing report with HTTP 200."""
    payload = {
        "url": "https://malware.test/download.exe",
        "category": "malware",
        "claimed_verdict": "MALICIOUS",
        "evidence_text": "Page delivers an obfuscated executable payload without user consent or signature.",
    }
    resp1 = await client.post(
        "/api/v1/community/reports",
        json=payload,
        headers=regular_reporter["headers"],
    )
    assert resp1.status_code == 201
    report_id = resp1.json()["report"]["id"]

    # Submit second time immediately
    resp2 = await client.post(
        "/api/v1/community/reports",
        json=payload,
        headers=regular_reporter["headers"],
    )
    assert resp2.status_code == 200
    assert resp2.json()["duplicate_submission"] is True
    assert resp2.json()["report"]["id"] == report_id


@pytest.mark.asyncio
async def test_submit_report_ssrf_destination_rejected(
    client: AsyncClient,
    regular_reporter: dict,
) -> None:
    """Verify SSRF protection blocks reports targeting private or loopback destinations."""
    payload = {
        "url": "http://127.0.0.1:80/admin",
        "category": "other",
        "claimed_verdict": "MALICIOUS",
        "evidence_text": "Attempting to submit private loopback IP address destination.",
    }
    resp = await client.post(
        "/api/v1/community/reports",
        json=payload,
        headers=regular_reporter["headers"],
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "TARGET_NOT_PUBLIC"


@pytest.mark.asyncio
async def test_list_public_reports_only_confirmed(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
) -> None:
    """Verify public community feed strictly excludes pending or rejected reports."""
    # Seed 1 pending and 1 confirmed report
    pending_rep = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://pending-example.com",
        canonical_url="https://pending-example.com",
        host="pending-example.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Pending report evidence explanation 1234567890",
        status="pending",
    )
    confirmed_rep = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://confirmed-example.com",
        canonical_url="https://confirmed-example.com",
        host="confirmed-example.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Confirmed report evidence explanation 1234567890",
        status="confirmed",
    )
    db_session.add_all([pending_rep, confirmed_rep])
    await db_session.commit()

    resp = await client.get("/api/v1/community/reports")
    assert resp.status_code == 200
    data = resp.json()
    hosts = [item["host"] for item in data["items"]]
    assert "confirmed-example.com" in hosts
    assert "pending-example.com" not in hosts


@pytest.mark.asyncio
async def test_list_user_reports_shows_own_submissions(
    client: AsyncClient,
    regular_reporter: dict,
) -> None:
    """Verify reporter can query their own submissions in any status."""
    payload = {
        "url": "https://phishing.test/my-sub",
        "category": "phishing",
        "claimed_verdict": "MALICIOUS",
        "evidence_text": "Personal submission testing user reports list retrieval 123456.",
    }
    await client.post(
        "/api/v1/community/reports",
        json=payload,
        headers=regular_reporter["headers"],
    )

    resp = await client.get("/api/v1/community/reports/mine", headers=regular_reporter["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(item["canonical_url"] == "https://phishing.test/my-sub" for item in data["items"])


@pytest.mark.asyncio
async def test_report_detail_visibility_rules(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
    community_voter: dict,
) -> None:
    """Verify pending report is hidden from public and non-owners, but visible to owner."""
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://secret-pending.com",
        canonical_url="https://secret-pending.com",
        host="secret-pending.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Detailed pending report test evidence text 1234567890.",
        status="pending",
    )
    db_session.add(report)
    await db_session.commit()

    # Anonymous user -> 404
    resp_anon = await client.get(f"/api/v1/community/reports/{report.id}")
    assert resp_anon.status_code == 404

    # Other non-owner user -> 404
    resp_other = await client.get(
        f"/api/v1/community/reports/{report.id}", headers=community_voter["headers"]
    )
    assert resp_other.status_code == 404

    # Report owner -> 200
    resp_owner = await client.get(
        f"/api/v1/community/reports/{report.id}", headers=regular_reporter["headers"]
    )
    assert resp_owner.status_code == 200
    assert resp_owner.json()["report"]["id"] == str(report.id)


@pytest.mark.asyncio
async def test_voting_on_confirmed_report(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
    community_voter: dict,
) -> None:
    """Verify community users can vote on confirmed reports, update votes, and cannot vote on own reports."""
    # Create confirmed report
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://votable.com",
        canonical_url="https://votable.com",
        host="votable.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Votable confirmed report description with adequate length 12345.",
        status="confirmed",
    )
    db_session.add(report)
    await db_session.commit()

    # 1. Reporter cannot vote on own report
    resp_own = await client.post(
        f"/api/v1/community/reports/{report.id}/votes",
        json={"vote": "confirm"},
        headers=regular_reporter["headers"],
    )
    assert resp_own.status_code == 403
    assert resp_own.json()["error"]["code"] == "OWN_REPORT_VOTE_NOT_ALLOWED"

    # 2. Distinct user votes "confirm"
    resp_vote = await client.post(
        f"/api/v1/community/reports/{report.id}/votes",
        json={"vote": "confirm"},
        headers=community_voter["headers"],
    )
    assert resp_vote.status_code == 200
    data = resp_vote.json()
    assert data["vote"] == "confirm"
    assert data["updated"] is False
    assert data["counts"]["confirm"] == 1
    assert data["counts"]["false_positive"] == 0

    # 3. Same user updates vote to "false_positive"
    resp_update = await client.post(
        f"/api/v1/community/reports/{report.id}/votes",
        json={"vote": "false_positive"},
        headers=community_voter["headers"],
    )
    assert resp_update.status_code == 200
    data_up = resp_update.json()
    assert data_up["vote"] == "false_positive"
    assert data_up["updated"] is True
    assert data_up["counts"]["confirm"] == 0
    assert data_up["counts"]["false_positive"] == 1


@pytest.mark.asyncio
async def test_voting_on_pending_report_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
    community_voter: dict,
) -> None:
    """Verify voting on an unconfirmed pending report returns HTTP 409 REPORT_NOT_VOTABLE."""
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://unconfirmed-report.com",
        canonical_url="https://unconfirmed-report.com",
        host="unconfirmed-report.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Unconfirmed report description with adequate length 1234567.",
        status="pending",
    )
    db_session.add(report)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/community/reports/{report.id}/votes",
        json={"vote": "confirm"},
        headers=community_voter["headers"],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "REPORT_NOT_VOTABLE"


@pytest.mark.asyncio
async def test_moderation_by_regular_user_forbidden(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
) -> None:
    """Verify regular user calling moderator endpoints receives HTTP 403."""
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://pending-target.com",
        canonical_url="https://pending-target.com",
        host="pending-target.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Target for moderation authorization test 1234567890.",
        status="pending",
    )
    db_session.add(report)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/admin/reports/{report.id}/moderation",
        json={"decision": "confirmed", "reason": "Attempting moderation as regular user."},
        headers=regular_reporter["headers"],
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_moderation_by_moderator_succeeds_and_creates_audit_event(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
    moderator_user: dict,
) -> None:
    """Verify moderator can confirm report with valid reason, creating audit log atomically."""
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://legit-phish.com",
        canonical_url="https://legit-phish.com",
        host="legit-phish.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Verified phishing page mimicking banking credentials form.",
        status="pending",
    )
    db_session.add(report)
    await db_session.commit()

    reason = "Corroborated by independent threat indicators and brand spoofing."
    resp = await client.post(
        f"/api/v1/admin/reports/{report.id}/moderation",
        json={"decision": "confirmed", "reason": reason},
        headers=moderator_user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["report"]["status"] == "confirmed"
    assert data["report"]["moderator_user_id"] == str(moderator_user["user_id"])
    assert data["report"]["moderation_reason"] == reason
    assert "audit_event_id" in data

    # Verify audit event in database
    audit_stmt = select(AuditEvent).where(AuditEvent.id == uuid.UUID(data["audit_event_id"]))
    audit_res = await db_session.execute(audit_stmt)
    audit = audit_res.scalar_one_or_none()
    assert audit is not None
    assert audit.action == "report.moderated"
    assert audit.actor_user_id == moderator_user["user_id"]
    assert audit.target_id == report.id


@pytest.mark.asyncio
async def test_moderation_state_conflict(
    client: AsyncClient,
    db_session: AsyncSession,
    regular_reporter: dict,
    moderator_user: dict,
) -> None:
    """Verify re-moderating an already confirmed report returns HTTP 409 STATE_CONFLICT."""
    report = CommunityReport(
        id=uuid.uuid4(),
        reporter_user_id=regular_reporter["user_id"],
        original_url="https://already-confirmed.com",
        canonical_url="https://already-confirmed.com",
        host="already-confirmed.com",
        category="phishing",
        claimed_verdict="MALICIOUS",
        evidence_text="Report already confirmed earlier in workflow 123456789.",
        status="confirmed",
    )
    db_session.add(report)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/admin/reports/{report.id}/moderation",
        json={"decision": "rejected", "reason": "Attempting second moderation decision."},
        headers=moderator_user["headers"],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "STATE_CONFLICT"


@pytest.mark.asyncio
async def test_admin_providers_endpoint(
    client: AsyncClient,
    moderator_user: dict,
) -> None:
    """Verify moderator can retrieve provider freshness and operational status."""
    resp = await client.get("/api/v1/admin/providers", headers=moderator_user["headers"])
    assert resp.status_code == 200
    providers = resp.json()["providers"]
    assert len(providers) >= 2
    names = [p["provider"] for p in providers]
    assert "openphish" in names
    assert "urlhaus" in names
