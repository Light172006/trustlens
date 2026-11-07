"""Tests for application health and foundation endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_returns_alive(client: AsyncClient) -> None:
    """Verify base health endpoint returns 200 and expected metadata."""
    response = await client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "alive"
    assert data["service"] == "trustlens-api"
    assert "version" in data
    assert "timestamp" in data
    assert "environment" in data


@pytest.mark.asyncio
async def test_health_live_endpoint(client: AsyncClient) -> None:
    """Verify container liveness probe."""
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


@pytest.mark.asyncio
async def test_security_headers_and_request_id_present(client: AsyncClient) -> None:
    """Verify standard security headers and correlation ID are set on responses."""
    response = await client.get("/health")
    assert response.status_code == 200

    headers = response.headers
    assert "X-Request-ID" in headers
    assert headers["X-Request-ID"].startswith("req_")
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_custom_request_id_propagated(client: AsyncClient) -> None:
    """Verify client-supplied X-Request-ID is preserved."""
    client_req_id = "req_custom_trace_12345"
    response = await client.get("/health", headers={"X-Request-ID": client_req_id})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == client_req_id


@pytest.mark.asyncio
async def test_database_health_probe(client: AsyncClient) -> None:
    """Verify database health probe returns structured DependencyHealthResponse."""
    response = await client.get("/health/database")
    # Response code is either 200 (if connected) or 503 (if mock/offline in test)
    assert response.status_code in (200, 503)

    data = response.json()
    assert "status" in data
    assert data["dependency"] == "database"
    assert "latency_ms" in data
    assert "message" in data


@pytest.mark.asyncio
async def test_redis_health_probe(client: AsyncClient) -> None:
    """Verify Redis health probe returns structured DependencyHealthResponse without leaking secrets."""
    response = await client.get("/health/redis")
    assert response.status_code in (200, 503)

    data = response.json()
    assert "status" in data
    assert data["dependency"] == "redis"
    assert "latency_ms" in data
    assert "message" in data
    # Ensure no credentials leaked in error message
    assert "password" not in data["message"].lower()


@pytest.mark.asyncio
async def test_readiness_probe(client: AsyncClient) -> None:
    """Verify composite readiness probe response structure."""
    response = await client.get("/health/ready")
    assert response.status_code in (200, 503)

    data = response.json()
    assert data["status"] in ("ready", "degraded")
    assert "checks" in data
    assert "database" in data["checks"]
    assert "redis" in data["checks"]


@pytest.mark.asyncio
async def test_not_found_returns_standard_error_envelope(client: AsyncClient) -> None:
    """Verify non-existent routes return standard API error envelope."""
    response = await client.get("/non-existent-endpoint-path")
    assert response.status_code == 404

    data = response.json()
    assert "error" in data
    error = data["error"]
    assert error["code"] == "RESOURCE_NOT_FOUND"
    assert "message" in error
    assert "request_id" in error
