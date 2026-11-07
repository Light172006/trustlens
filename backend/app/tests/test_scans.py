"""Automated tests for scan submission, deduplication, report retrieval, and access control."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.scanners import url_validator
from app.scanners.dns_scanner import DnsScanResult
from app.scanners.http_scanner import HttpScanResult
from app.scanners.redirect_scanner import RedirectScanResult
from app.scanners.security_headers import SecurityHeadersResult
from app.scanners.tls_scanner import TlsScanResult
from app.workers.scan_tasks import execute_scan_task, run_scan_pipeline


@pytest.fixture(autouse=True)
def mock_network_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock external DNS queries and Celery broker connection for fast, isolated tests."""
    # Fast deterministic DNS resolution for example.com
    original_resolve = url_validator.resolve_hostname_ips

    def _mock_resolve(hostname: str) -> list[str]:
        if "example.com" in hostname:
            return ["93.184.216.34"]
        return original_resolve(hostname)

    monkeypatch.setattr(url_validator, "resolve_hostname_ips", _mock_resolve)

    # Disable celery broker connection attempts in tests
    monkeypatch.setattr(execute_scan_task, "delay", lambda *args, **kwargs: None)


@pytest.fixture
async def registered_user(client: AsyncClient) -> dict:
    """Create a standard registered user and return auth headers."""
    payload = {
        "email": f"scanner.test.{uuid.uuid4().hex[:8]}@example.com",
        "password": "ScanPassword123!",
        "display_name": "Scanner Tester",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    token = resp.json()["tokens"]["access_token"]
    user_id = resp.json()["user"]["id"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": user_id,
        "email": payload["email"],
    }


@pytest.fixture
async def second_user(client: AsyncClient) -> dict:
    """Create a second distinct user for isolation testing."""
    payload = {
        "email": f"other.user.{uuid.uuid4().hex[:8]}@example.com",
        "password": "OtherPassword123!",
        "display_name": "Other User",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    token = resp.json()["tokens"]["access_token"]
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "user_id": resp.json()["user"]["id"],
    }


@pytest.mark.asyncio
async def test_submit_valid_scan_returns_202(client: AsyncClient, registered_user: dict) -> None:
    """Verify submitting a valid public URL creates a scan with QUEUED status and returns 202."""
    payload = {
        "url": "https://example.com/test-path",
        "treat_as_sensitive": False,
    }
    response = await client.post("/api/v1/scans", json=payload, headers=registered_user["headers"])
    assert response.status_code == 202

    data = response.json()
    assert "scan" in data
    assert data["deduplicated"] is False

    scan = data["scan"]
    assert scan["status"] == "queued"
    assert scan["verdict"] == "INCONCLUSIVE"
    assert scan["host"] == "example.com"
    assert scan["scheme"] == "https"
    assert scan["is_sensitive"] is False


@pytest.mark.asyncio
async def test_submit_duplicate_scan_within_60s_returns_200(
    client: AsyncClient, registered_user: dict
) -> None:
    """Verify deduplication returns HTTP 200 with deduplicated=true for duplicate submission within 60s."""
    payload = {
        "url": "https://example.com/dedup-check",
    }
    resp1 = await client.post("/api/v1/scans", json=payload, headers=registered_user["headers"])
    assert resp1.status_code == 202
    scan_id_1 = resp1.json()["scan"]["id"]

    # Submit identical URL immediately
    resp2 = await client.post("/api/v1/scans", json=payload, headers=registered_user["headers"])
    assert resp2.status_code == 200
    assert resp2.json()["deduplicated"] is True
    assert resp2.json()["scan"]["id"] == scan_id_1


@pytest.mark.asyncio
async def test_submit_ssrf_url_rejected(client: AsyncClient, registered_user: dict) -> None:
    """Verify submitting a private IP destination is rejected before creating a scan."""
    payload = {
        "url": "http://127.0.0.1:80/admin",
    }
    response = await client.post("/api/v1/scans", json=payload, headers=registered_user["headers"])
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "TARGET_NOT_PUBLIC"


@pytest.mark.asyncio
async def test_list_scans_owner_isolation(
    client: AsyncClient,
    registered_user: dict,
    second_user: dict,
) -> None:
    """Verify user only sees scans they own."""
    # User 1 submits a scan
    payload = {"url": "https://example.com/user1-target"}
    await client.post("/api/v1/scans", json=payload, headers=registered_user["headers"])

    # User 2 lists scans -> must be empty
    resp_user2 = await client.get("/api/v1/scans", headers=second_user["headers"])
    assert resp_user2.status_code == 200
    data2 = resp_user2.json()
    assert data2["total"] == 0
    assert len(data2["items"]) == 0

    # User 1 lists scans -> must contain 1 scan
    resp_user1 = await client.get("/api/v1/scans", headers=registered_user["headers"])
    assert resp_user1.status_code == 200
    assert resp_user1.json()["total"] >= 1


@pytest.mark.asyncio
async def test_get_scan_detail_owner_isolation(
    client: AsyncClient,
    registered_user: dict,
    second_user: dict,
) -> None:
    """Verify User B cannot access scan report owned by User A."""
    payload = {"url": "https://example.com/private-scan"}
    create_resp = await client.post(
        "/api/v1/scans", json=payload, headers=registered_user["headers"]
    )
    scan_id = create_resp.json()["scan"]["id"]

    # User 1 can view scan
    resp_owner = await client.get(f"/api/v1/scans/{scan_id}", headers=registered_user["headers"])
    assert resp_owner.status_code == 200
    assert resp_owner.json()["scan"]["id"] == scan_id

    # User 2 access is forbidden
    resp_other = await client.get(f"/api/v1/scans/{scan_id}", headers=second_user["headers"])
    assert resp_other.status_code == 403


@pytest.mark.asyncio
async def test_scan_pipeline_execution_and_findings(
    client: AsyncClient,
    registered_user: dict,
) -> None:
    """Verify end-to-end execution of scan pipeline and findings persistence with mocked scanners."""
    payload = {"url": "https://example.com/live-scan"}
    create_resp = await client.post(
        "/api/v1/scans", json=payload, headers=registered_user["headers"]
    )
    scan_id = create_resp.json()["scan"]["id"]

    # Mock scanner network calls to avoid external network dependencies and latency
    mock_dns = DnsScanResult(host="example.com", a_records=["93.184.216.34"], completed=True)
    mock_http = HttpScanResult(
        initial_url="https://example.com/live-scan",
        final_url="https://example.com/live-scan",
        status_code=200,
        response_time_ms=45.2,
        content_type="text/html; charset=UTF-8",
        content_length=1256,
        redirects=RedirectScanResult(final_url="https://example.com/live-scan", redirect_count=0),
        security_headers=SecurityHeadersResult(
            raw_headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            }
        ),
        completed=True,
    )
    mock_tls = TlsScanResult(
        host="example.com",
        valid=True,
        chain_valid=True,
        hostname_match=True,
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        completed=True,
    )

    with (
        patch("app.workers.scan_tasks.dns_scanner.scan", return_value=mock_dns),
        patch(
            "app.workers.scan_tasks.http_scanner.scan",
            new_callable=AsyncMock,
            return_value=mock_http,
        ),
        patch("app.workers.scan_tasks.tls_scanner.scan", return_value=mock_tls),
    ):
        # Execute scan pipeline directly
        await run_scan_pipeline(scan_id=scan_id, allow_private_for_tests=True)

    # Inspect scan report
    report_resp = await client.get(f"/api/v1/scans/{scan_id}", headers=registered_user["headers"])
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["scan"]["status"] in ("succeeded", "partial")
    assert report_data["scan"]["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE")
    assert "coverage" in report_data
    assert "provider_checks" in report_data

    # Inspect findings endpoint
    findings_resp = await client.get(
        f"/api/v1/scans/{scan_id}/findings", headers=registered_user["headers"]
    )
    assert findings_resp.status_code == 200
    assert "items" in findings_resp.json()


@pytest.mark.asyncio
async def test_delete_scan_endpoint(
    client: AsyncClient,
    registered_user: dict,
) -> None:
    """Verify deleting an owned scan removes it and subsequent gets return 404."""
    payload = {"url": "https://example.com/to-delete"}
    create_resp = await client.post(
        "/api/v1/scans", json=payload, headers=registered_user["headers"]
    )
    scan_id = create_resp.json()["scan"]["id"]

    del_resp = await client.delete(f"/api/v1/scans/{scan_id}", headers=registered_user["headers"])
    assert del_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/scans/{scan_id}", headers=registered_user["headers"])
    assert get_resp.status_code == 404
