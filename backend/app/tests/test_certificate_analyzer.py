"""Automated tests for the TrustLens Certificate Analyzer backend integration."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.integrations.certificate_client import certificate_client
from app.scanners import url_validator
from app.scanners.dns_scanner import DnsScanResult
from app.scanners.http_scanner import HttpScanResult
from app.scanners.redirect_scanner import RedirectScanResult
from app.scanners.security_headers import SecurityHeadersResult
from app.scanners.tls_scanner import TlsCertificateDetails, TlsScanResult
from app.workers.scan_tasks import execute_scan_task, run_scan_pipeline


@pytest.fixture(autouse=True)
def mock_network_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock external network DNS lookups and Celery background task queuing."""
    monkeypatch.setattr(
        url_validator,
        "resolve_hostname_ips",
        lambda hostname: ["93.184.216.34"],
    )
    monkeypatch.setattr(execute_scan_task, "delay", lambda *args, **kwargs: None)


def generate_test_certificate(
    common_name: str = "example.com",
    days_valid: int = 30,
    san_names: list[str] | None = None,
) -> tuple[bytes, str]:
    """Generate self-signed certificate returning (der_bytes, pem_str)."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TrustLens Testing Corp"),
        ]
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    if san_names:
        sans = [x509.DNSName(name) for name in san_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return der, pem


@pytest.fixture
async def auth_user(client: AsyncClient) -> dict:
    """Register a user and return authorization header."""
    payload = {
        "email": f"cert.tester.{uuid.uuid4().hex[:8]}@example.com",
        "password": "CertPassword123!",
        "display_name": "Certificate Tester",
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


# ============================================================================
# 1. Integration Client Unit Tests
# ============================================================================


def test_certificate_client_initialization() -> None:
    """Verifies CertificateAnalyzerClient is ready and linked to underlying engine."""
    assert certificate_client is not None
    assert certificate_client.is_available is True


def test_certificate_client_analyze_pem() -> None:
    """Tests evaluating a valid PEM certificate."""
    _, pem = generate_test_certificate(
        common_name="app.trustlens.io",
        days_valid=45,
        san_names=["app.trustlens.io"],
    )
    assessment = certificate_client.analyze_pem(
        pem_data=pem,
        target_hostname="app.trustlens.io",
    )
    assert assessment is not None
    # Verify deterministic fields
    assert assessment.verdict in ("TRUSTED", "WARNING", "DISTRUSTED", "INCONCLUSIVE")
    assert assessment.certificate_sha256 != ""
    assert assessment.confidence > 0.0
    assert assessment.checks_completed > 0
    # Because it is self-signed, should emit finding
    codes = [f.code for f in assessment.findings]
    assert "RULE_SELF_SIGNED_LEAF" in codes or "RULE_SELF_SIGNED_SUBSCRIBER" in codes


def test_certificate_client_rfc9525_hostname_mismatch() -> None:
    """Tests RFC 9525 identity validation detecting mismatch."""
    _, pem = generate_test_certificate(
        common_name="legitimate.com",
        san_names=["legitimate.com"],
    )
    assessment = certificate_client.analyze_pem(
        pem_data=pem,
        target_hostname="phishing-impostor.com",
    )
    codes = [f.code for f in assessment.findings]
    assert "RULE_HOSTNAME_MISMATCH" in codes
    assert assessment.verdict == "DISTRUSTED"


def test_certificate_client_fail_safe_malformed_input() -> None:
    """Tests non-crashing fail-safe contract on corrupt input bytes."""
    corrupt_data = b"NOT_A_VALID_DER_ASN1_CERTIFICATE_JUST_NOISE"
    assessment = certificate_client.analyze_certificate(
        certificate_input=corrupt_data,
        target_hostname="example.com",
    )
    assert assessment is not None
    assert assessment.verdict == "INCONCLUSIVE"
    assert assessment.trust_score == 0
    assert assessment.confidence == 0.0
    codes = [f.code for f in assessment.findings]
    assert "RULE_MALFORMED_CERTIFICATE" in codes


def test_certificate_client_resource_limit_defense() -> None:
    """Tests rejection of oversized inputs exceeding 10 MB ceiling."""
    oversized_data = b"0" * (10485760 + 1024)
    assessment = certificate_client.analyze_certificate(
        certificate_input=oversized_data,
        target_hostname="example.com",
    )
    assert assessment is not None
    assert assessment.verdict == "INCONCLUSIVE"
    codes = [f.code for f in assessment.findings]
    assert "RULE_RESOURCE_LIMIT_EXCEEDED" in codes


# ============================================================================
# 2. REST API Endpoint Tests
# ============================================================================


@pytest.mark.anyio
async def test_api_analyze_certificate_pem(client: AsyncClient, auth_user: dict) -> None:
    """POST /api/v1/certificates/analyze using PEM format."""
    _, pem = generate_test_certificate(
        common_name="api.trustlens.io",
        days_valid=90,
        san_names=["api.trustlens.io"],
    )
    payload = {
        "target_hostname": "api.trustlens.io",
        "certificate_pem": pem,
    }
    resp = await client.post(
        "/api/v1/certificates/analyze",
        json=payload,
        headers=auth_user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["certificate_sha256"] != ""
    assert data["target_hostname"] == "api.trustlens.io"
    assert "verdict" in data
    assert "trust_score" in data
    assert "findings" in data
    assert len(data["findings"]) > 0
    assert data["id"] is not None


@pytest.mark.anyio
async def test_api_analyze_certificate_der_base64(client: AsyncClient, auth_user: dict) -> None:
    """POST /api/v1/certificates/analyze using base64-encoded DER format."""
    der_bytes, _ = generate_test_certificate(
        common_name="secure.service.org",
        days_valid=60,
        san_names=["secure.service.org"],
    )
    b64_der = base64.b64encode(der_bytes).decode("ascii")
    payload = {
        "target_hostname": "secure.service.org",
        "port": 443,
        "tls_protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "certificate_der_base64": b64_der,
    }
    resp = await client.post(
        "/api/v1/certificates/analyze",
        json=payload,
        headers=auth_user["headers"],
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["certificate_sha256"] != ""
    assert data["verdict"] in ("TRUSTED", "WARNING", "DISTRUSTED", "INCONCLUSIVE")


@pytest.mark.anyio
async def test_api_get_certificate_assessment_by_id(client: AsyncClient, auth_user: dict) -> None:
    """GET /api/v1/certificates/{id} retrieves previously stored assessment."""
    _, pem = generate_test_certificate(common_name="retrieve.test.net")
    analyze_resp = await client.post(
        "/api/v1/certificates/analyze",
        json={"certificate_pem": pem, "target_hostname": "retrieve.test.net"},
        headers=auth_user["headers"],
    )
    assert analyze_resp.status_code == 200
    cert_id = analyze_resp.json()["id"]

    get_resp = await client.get(
        f"/api/v1/certificates/{cert_id}",
        headers=auth_user["headers"],
    )
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["id"] == cert_id
    assert retrieved["target_hostname"] == "retrieve.test.net"
    assert retrieved["verdict"] == analyze_resp.json()["verdict"]


@pytest.mark.anyio
async def test_api_list_certificate_assessments(client: AsyncClient, auth_user: dict) -> None:
    """GET /api/v1/certificates lists user's certificate assessments."""
    _, pem = generate_test_certificate(common_name="listed.domain.com")
    await client.post(
        "/api/v1/certificates/analyze",
        json={"certificate_pem": pem, "target_hostname": "listed.domain.com"},
        headers=auth_user["headers"],
    )

    list_resp = await client.get(
        "/api/v1/certificates?limit=10&offset=0",
        headers=auth_user["headers"],
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert "items" in data
    assert data["total"] >= 1
    assert any(item["target_hostname"] == "listed.domain.com" for item in data["items"])


@pytest.mark.anyio
async def test_api_analyze_missing_inputs(client: AsyncClient, auth_user: dict) -> None:
    """POST /api/v1/certificates/analyze without DER, PEM, or hostname returns 422."""
    resp = await client.post(
        "/api/v1/certificates/analyze",
        json={},
        headers=auth_user["headers"],
    )
    assert resp.status_code == 422


# ============================================================================
# 3. Full Website Scan Pipeline Certificate Integration
# ============================================================================


@pytest.mark.anyio
async def test_scan_pipeline_persists_enriched_certificate(
    client: AsyncClient,
    db_session: AsyncSession,
    auth_user: dict,
) -> None:
    """Verifies that running a website scan executes certificate intelligence and enriches Certificate record."""
    der_bytes, _ = generate_test_certificate(
        common_name="scan.pipeline.test",
        san_names=["scan.pipeline.test"],
    )

    # Submit website scan
    submit_resp = await client.post(
        "/api/v1/scans",
        json={"url": "https://scan.pipeline.test"},
        headers=auth_user["headers"],
    )
    assert submit_resp.status_code == 202
    scan_id = uuid.UUID(submit_resp.json()["scan"]["id"])

    from unittest.mock import AsyncMock, patch

    # Prepare mock scan telemetry
    mock_dns = DnsScanResult(
        host="scan.pipeline.test",
        a_records=["93.184.216.34"],
        completed=True,
    )
    mock_http = HttpScanResult(
        initial_url="https://scan.pipeline.test",
        final_url="https://scan.pipeline.test",
        status_code=200,
        response_time_ms=40.0,
        redirects=RedirectScanResult(final_url="https://scan.pipeline.test", redirect_count=0),
        security_headers=SecurityHeadersResult(),
        completed=True,
    )

    # Pre-evaluate assessment on test certificate
    assessment = certificate_client.analyze_endpoint_tls(
        certificate_der=der_bytes,
        target_hostname="scan.pipeline.test",
    )
    assessment_dict = (
        assessment.model_dump(mode="json")
        if hasattr(assessment, "model_dump")
        else dict(assessment)
    )

    tls_res = TlsScanResult(
        host="scan.pipeline.test",
        port=443,
        valid=True,
        chain_valid=True,
        hostname_match=True,
        raw_leaf_der=der_bytes,
        assessment=assessment_dict,
        certificate=TlsCertificateDetails(
            leaf_fingerprint_sha256=assessment_dict["certificate_sha256"],
            serial_number="123456",
            subject_cn="scan.pipeline.test",
            san_dns=["scan.pipeline.test"],
            issuer="TrustLens Testing Corp",
            not_before=datetime.now(UTC) - timedelta(days=1),
            not_after=datetime.now(UTC) + timedelta(days=30),
            days_until_expiry=30,
            is_expired=False,
            expires_soon=False,
            signature_algorithm="sha256WithRSAEncryption",
            public_key_algorithm="RSA",
            public_key_bits=2048,
            sct_present=False,
        ),
        completed=True,
    )

    # Run the pipeline with mocked scanners
    with (
        patch("app.workers.scan_tasks.dns_scanner.scan", return_value=mock_dns),
        patch(
            "app.workers.scan_tasks.http_scanner.scan",
            new_callable=AsyncMock,
            return_value=mock_http,
        ),
        patch("app.workers.scan_tasks.tls_scanner.scan", return_value=tls_res),
    ):
        await run_scan_pipeline(scan_id=scan_id, allow_private_for_tests=True)

    # Query GET /api/v1/scans/{scan_id}/certificate
    cert_endpoint_resp = await client.get(
        f"/api/v1/scans/{scan_id}/certificate",
        headers=auth_user["headers"],
    )
    assert cert_endpoint_resp.status_code == 200
    data = cert_endpoint_resp.json()
    assert data["available"] is True
    assert data["certificate"] is not None
    cert_info = data["certificate"]
    assert cert_info["host"] == "scan.pipeline.test"
    # Enriched intelligence metrics
    assert "verdict" in cert_info
    assert cert_info["verdict"] in ("TRUSTED", "WARNING", "DISTRUSTED", "INCONCLUSIVE")
    assert "trust_score" in cert_info
    assert "confidence" in cert_info
