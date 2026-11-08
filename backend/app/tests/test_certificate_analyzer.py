"""Automated tests for Certificate Analyzer endpoints and backend integration."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from httpx import AsyncClient

from app.models.certificate import Certificate, CertificateScan
from app.models.scan import Scan
from app.scanners import url_validator
from app.workers.scan_tasks import execute_scan_task


@pytest.fixture(autouse=True)
def mock_network_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock external DNS queries and Celery broker connection for fast, isolated tests."""
    original_resolve = url_validator.resolve_hostname_ips

    def _mock_resolve(hostname: str) -> list[str]:
        if "example.com" in hostname or "trustlens.io" in hostname:
            return ["93.184.216.34"]
        return original_resolve(hostname)

    monkeypatch.setattr(url_validator, "resolve_hostname_ips", _mock_resolve)
    monkeypatch.setattr(execute_scan_task, "delay", lambda *args, **kwargs: None)


@pytest.fixture
def test_certificate_pem() -> str:
    """Generate a clean in-memory X.509 certificate in PEM format."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.trustlens.io")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.trustlens.io")]))
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - timedelta(days=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.trustlens.io")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
def expired_certificate_pem() -> str:
    """Generate an expired in-memory X.509 certificate in PEM format."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    past = datetime(2021, 1, 1, tzinfo=UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired.trustlens.io")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "expired.trustlens.io")]))
        .public_key(key.public_key())
        .serial_number(987654321)
        .not_valid_before(past)
        .not_valid_after(past + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("expired.trustlens.io")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
async def authenticated_headers(client: AsyncClient) -> dict[str, str]:
    """Register user and return auth headers."""
    payload = {
        "email": f"cert.test.{uuid.uuid4().hex[:8]}@example.com",
        "password": "CertPassword123!",
        "display_name": "Cert Tester",
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201
    token = resp.json()["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_direct_pem_analysis_returns_assessment(
    client: AsyncClient, test_certificate_pem: str
) -> None:
    """Verify POST /api/v1/certificates/analyze successfully assesses valid PEM."""
    payload = {
        "pem": test_certificate_pem,
        "hostname": "test.trustlens.io",
        "include_ml_advisory": True,
    }
    response = await client.post("/api/v1/certificates/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "verdict" in data
    assert "trust_score" in data
    assert "confidence" in data
    assert "findings" in data
    assert "policy_evaluation" in data
    assert data["features"]["has_san"] is True
    assert data["features"]["matches_tested_hostname"] is True


@pytest.mark.asyncio
async def test_direct_expired_pem_analysis_yields_distrusted(
    client: AsyncClient, expired_certificate_pem: str
) -> None:
    """Verify expired certificate receives DISTRUSTED verdict and score = 0."""
    payload = {
        "pem": expired_certificate_pem,
        "hostname": "expired.trustlens.io",
    }
    response = await client.post("/api/v1/certificates/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["verdict"] == "DISTRUSTED"
    assert data["trust_score"] == 0
    assert any(f["code"] == "RULE_EXPIRED" for f in data["findings"])


@pytest.mark.asyncio
async def test_certificate_analyze_empty_request_rejected(client: AsyncClient) -> None:
    """Verify empty request with neither hostname nor pem is rejected with 422."""
    response = await client.post("/api/v1/certificates/analyze", json={})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_certificate_analyze_ssrf_blocked(client: AsyncClient) -> None:
    """Verify SSRF loopback/private target is rejected before establishing connection."""
    payload = {
        "hostname": "127.0.0.1",
        "port": 443,
    }
    response = await client.post("/api/v1/certificates/analyze", json=payload)
    assert response.status_code == 400
    err_body = response.json()
    assert "error" in err_body
    assert err_body["error"]["code"] == "TARGET_NOT_PUBLIC"


@pytest.mark.asyncio
async def test_scan_certificate_endpoint_returns_rich_assessment(
    client: AsyncClient, authenticated_headers: dict[str, str]
) -> None:
    """Verify GET /api/v1/scans/{scan_id}/certificate returns full assessment payload."""
    # 1. Submit scan
    scan_resp = await client.post(
        "/api/v1/scans",
        json={"url": "https://example.com/cert-test"},
        headers=authenticated_headers,
    )
    assert scan_resp.status_code in (200, 202)
    scan_id = scan_resp.json()["scan"]["id"]

    # 2. Query certificate details
    cert_resp = await client.get(
        f"/api/v1/scans/{scan_id}/certificate",
        headers=authenticated_headers,
    )
    assert cert_resp.status_code == 200
    data = cert_resp.json()
    assert "available" in data
    assert data["scan_id"] == scan_id
