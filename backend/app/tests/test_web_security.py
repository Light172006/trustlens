"""Tests for Web Security Analysis endpoints and service layer."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app as fastapi_app


@pytest.fixture
def mock_web_security_report() -> Any:
    """Generates a mock WebSecurityReport dictionary/object."""
    from analyzer.models import (  # type: ignore
        ConsensusModel,
        FindingsSummaryModel,
        MLPredictionModel,
        RemediationItemModel,
        SecurityFindingModel,
        WebSecurityReport,
    )

    return WebSecurityReport(
        target_url="https://secure-target.example.org",
        normalized_domain="secure-target.example.org",
        registrable_domain="example.org",
        scan_timestamp="2026-11-08T22:00:00Z",
        scanner_version="1.0.0",
        posture="GOOD",
        security_score=88.5,
        deterministic_posture="GOOD",
        ml_prediction=MLPredictionModel(
            available=True,
            predicted_posture="GOOD",
            probabilities={"GOOD": 0.88, "MODERATE": 0.10, "POOR": 0.02},
            confidence=0.88,
            margin=0.78,
            abstained=False,
            model_name="HistGradientBoosting",
            model_version="1.0.0",
        ),
        consensus=ConsensusModel(
            status="CONSENSUS",
            discrepancy_explanation=None,
        ),
        findings_summary=FindingsSummaryModel(
            total_findings=2,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=1,
            pass_count=1,
            affected_categories=["HTTP_HEADERS"],
        ),
        findings=[
            SecurityFindingModel(
                finding_id="HDR-HSTS-PASS",
                category="HTTP_HEADERS",
                name="Strict-Transport-Security Configured",
                severity="PASS",
                status="COMPLIANT",
                evidence="max-age=31536000; includeSubDomains; preload",
                detection_method="DETERMINISTIC_RULE_INSPECTION",
                confidence=1.0,
                guidance="RFC 6797",
                recommendation=None,
            ),
            SecurityFindingModel(
                finding_id="HDR-CSP-LOW",
                category="HTTP_HEADERS",
                name="Missing Content-Security-Policy",
                severity="LOW",
                status="NON_COMPLIANT",
                evidence="Header missing",
                detection_method="DETERMINISTIC_RULE_INSPECTION",
                confidence=1.0,
                guidance="W3C CSP Level 3",
                recommendation="Configure a restrictive Content-Security-Policy header.",
            ),
        ],
        remediations=[
            RemediationItemModel(
                finding_id="HDR-CSP-LOW",
                severity="LOW",
                category="HTTP_HEADERS",
                recommendation="Configure a restrictive Content-Security-Policy header.",
            )
        ],
        telemetry={"status_code": 200, "hsts_present": True},
    )


@pytest.mark.asyncio
async def test_analyze_web_security_success(mock_web_security_report: Any) -> None:
    """Test successful web security analysis request."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch(
            "app.services.web_security_service.web_security_client.analyze_async",
            new_callable=AsyncMock,
        ) as mock_analyze:
            mock_analyze.return_value = mock_web_security_report

            response = await ac.post(
                "/api/v1/web-security/analyze",
                json={"url": "https://secure-target.example.org"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["target_url"] == "https://secure-target.example.org"
            assert data["normalized_domain"] == "secure-target.example.org"
            assert data["posture"] == "GOOD"
            assert data["security_score"] == 88.5
            assert data["consensus"]["status"] == "CONSENSUS"
            assert data["ml_prediction"]["predicted_posture"] == "GOOD"
            assert len(data["findings"]) == 2
            assert len(data["remediations"]) == 1
            assert data["id"] is not None


@pytest.mark.asyncio
async def test_analyze_web_security_handoff_alias(mock_web_security_report: Any) -> None:
    """Verify Section 7 handoff route alias POST /api/v1/analyze/web-security."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch(
            "app.services.web_security_service.web_security_client.analyze_async",
            new_callable=AsyncMock,
        ) as mock_analyze:
            mock_analyze.return_value = mock_web_security_report

            response = await ac.post(
                "/api/v1/analyze/web-security",
                json={"url": "https://secure-target.example.org"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["posture"] == "GOOD"
            assert data["security_score"] == 88.5


@pytest.mark.asyncio
async def test_analyze_certificate_handoff_alias(auth_user: dict[str, Any]) -> None:
    """Verify Section 7 handoff route alias POST /api/v1/analyze/certificate."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch(
            "app.services.certificate_service.certificate_service.analyze_certificate_request",
            new_callable=AsyncMock,
        ) as mock_analyze:
            from app.schemas.certificate import CertificateAssessmentResponse

            mock_analyze.return_value = CertificateAssessmentResponse(
                id=uuid.uuid4(),
                target_hostname="example.com",
                certificate_sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
                trust_score=95,
                verdict="TRUSTED",
                confidence=1.0,
                checks_completed=4,
                findings=[],
                policy_evaluation={"strict_compliance": True},
                ml_advisory=None,
                summary="Certificate is valid and trusted.",
            )

            response = await ac.post(
                "/api/v1/analyze/certificate",
                headers=auth_user["headers"],
                json={"target_hostname": "example.com"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["trust_score"] == 95
            assert data["verdict"] == "TRUSTED"


@pytest.mark.asyncio
async def test_analyze_web_security_ssrf_rejection() -> None:
    """Verify that private loopback addresses are blocked by WebSecurityAnalyzer SSRF policy."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/web-security/analyze",
            json={"url": "http://127.0.0.1:8080/admin"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["posture"] == "INSUFFICIENT_EVIDENCE"
        assert data["security_score"] == 0.0
        assert "SSRF" in data["consensus"]["discrepancy_explanation"]


@pytest.mark.asyncio
async def test_analyze_web_security_validation_error() -> None:
    """Verify rejection of empty or malformed URLs."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Missing URL
        response = await ac.post(
            "/api/v1/web-security/analyze",
            json={},
        )
        assert response.status_code in (400, 422)

        # Too short
        response = await ac.post(
            "/api/v1/web-security/analyze",
            json={"url": "a"},
        )
        assert response.status_code in (400, 422)


@pytest.mark.asyncio
async def test_get_and_list_web_security_scans(mock_web_security_report: Any) -> None:
    """Test retrieving by ID and paginated listing of web security scans."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with patch(
            "app.services.web_security_service.web_security_client.analyze_async",
            new_callable=AsyncMock,
        ) as mock_analyze:
            mock_analyze.return_value = mock_web_security_report

            # 1. Create a scan
            post_resp = await ac.post(
                "/api/v1/web-security/analyze",
                json={"url": "https://list-test.example.org"},
            )
            assert post_resp.status_code == 200
            scan_id = post_resp.json()["id"]

            # 2. Get by ID
            get_resp = await ac.get(f"/api/v1/web-security/{scan_id}")
            assert get_resp.status_code == 200
            get_data = get_resp.json()
            assert get_data["id"] == scan_id
            assert get_data["posture"] == "GOOD"

            # 3. List scans
            list_resp = await ac.get("/api/v1/web-security?limit=10&page=1")
            assert list_resp.status_code == 200
            list_data = list_resp.json()
            assert list_data["total"] >= 1
            assert any(item["id"] == scan_id for item in list_data["items"])


@pytest.mark.asyncio
async def test_get_web_security_scan_not_found() -> None:
    """Verify 404 for non-existent scan ID."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        random_id = uuid.uuid4()
        response = await ac.get(f"/api/v1/web-security/{random_id}")
        assert response.status_code == 404
