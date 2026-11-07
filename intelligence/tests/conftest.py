"""TrustLens Intelligence — Pytest Fixtures and Test Configurations.

Provides offline mock fixtures for clean, phishing, malware, and edge-case URLs.
"""

from typing import Any
import pytest

from trustlens_intelligence.config.settings import IntelligenceSettings
from trustlens_intelligence.schemas.evidence import (
    CommunityIntelligenceEvidence,
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    RedirectHopEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.threat_feeds.mock_provider import MockThreatProvider


@pytest.fixture
def clean_site_evidence() -> ScanEvidence:
    """Fixture representing a high-reputation, fully compliant HTTPS website."""
    return ScanEvidence(
        scan_id="scan_clean_001",
        original_url="https://www.example.org/security",
        canonical_url="https://www.example.org/security",
        host="www.example.org",
        scheme="https",
        is_sensitive=False,
        http=HttpEvidence(
            status_code=200,
            final_url="https://www.example.org/security",
            redirect_count=0,
            security_headers={
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=(), camera=()",
            },
            cookies=[
                CookieEvidence(name="session", secure=True, httponly=True, samesite="Lax")
            ],
            response_time_ms=120.0,
        ),
        tls=TlsCertificateEvidence(
            valid=True,
            chain_valid=True,
            hostname_match=True,
            days_until_expiry=180,
            is_expired=False,
            expires_soon=False,
            protocol_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            subject_cn="www.example.org",
            issuer="DigiCert Global Root CA",
            san_dns=["www.example.org", "example.org"],
            sct_present=True,
        ),
        domain_intelligence=DomainIntelligenceEvidence(
            domain_age_days=5200,
            registrar="MarkMonitor Inc.",
        ),
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=False,
            openphish_status="no_match",
            urlhaus_match=False,
            urlhaus_status="no_match",
        ),
        community_intelligence=CommunityIntelligenceEvidence(
            confirmed_report_count=0,
            distinct_reporter_count=0,
        ),
    )


@pytest.fixture
def phishing_site_evidence() -> ScanEvidence:
    """Fixture representing an active phishing URL with OpenPhish match."""
    return ScanEvidence(
        scan_id="scan_phish_002",
        original_url="http://secure-paypal-login-verify.com/account/login",
        canonical_url="http://secure-paypal-login-verify.com/account/login",
        host="secure-paypal-login-verify.com",
        scheme="http",
        is_sensitive=False,
        http=HttpEvidence(
            status_code=200,
            final_url="http://secure-paypal-login-verify.com/account/login",
            redirect_count=0,
            security_headers={},
            cookies=[],
        ),
        tls=None,
        domain_intelligence=DomainIntelligenceEvidence(
            domain_age_days=2,
            registrar="NameCheap",
        ),
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=True,
            openphish_status="match",
            urlhaus_match=False,
            urlhaus_status="no_match",
        ),
    )


@pytest.fixture
def malware_site_evidence() -> ScanEvidence:
    """Fixture representing an active malware site verified by URLhaus."""
    return ScanEvidence(
        scan_id="scan_malware_003",
        original_url="http://194.26.29.112/bin/updater.exe",
        canonical_url="http://194.26.29.112/bin/updater.exe",
        host="194.26.29.112",
        scheme="http",
        is_sensitive=False,
        http=HttpEvidence(
            status_code=200,
            final_url="http://194.26.29.112/bin/updater.exe",
            redirect_count=0,
            security_headers={},
            cookies=[],
        ),
        tls=None,
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=False,
            openphish_status="no_match",
            urlhaus_match=True,
            urlhaus_status="match",
            urlhaus_url_status="online",
        ),
    )


@pytest.fixture
def expired_cert_evidence() -> ScanEvidence:
    """Fixture representing a site with expired certificate and missing security headers."""
    return ScanEvidence(
        scan_id="scan_expired_004",
        original_url="https://expired-site.example.com",
        canonical_url="https://expired-site.example.com",
        host="expired-site.example.com",
        scheme="https",
        http=HttpEvidence(
            status_code=200,
            final_url="https://expired-site.example.com",
            security_headers={},
            cookies=[
                CookieEvidence(name="track_id", secure=False, httponly=False, samesite=None)
            ],
        ),
        tls=TlsCertificateEvidence(
            valid=False,
            chain_valid=True,
            hostname_match=True,
            days_until_expiry=-15,
            is_expired=True,
            protocol_version="TLSv1.2",
        ),
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=False,
            openphish_status="no_match",
            urlhaus_match=False,
            urlhaus_status="no_match",
        ),
    )


@pytest.fixture
def mock_openphish_provider() -> MockThreatProvider:
    return MockThreatProvider(
        name="openphish",
        matches={"http://known-phish.example/login"},
    )


@pytest.fixture
def mock_urlhaus_provider() -> MockThreatProvider:
    return MockThreatProvider(
        name="urlhaus",
        matches={"http://known-malware.example/payload.exe": {"url_status": "online"}},
    )

