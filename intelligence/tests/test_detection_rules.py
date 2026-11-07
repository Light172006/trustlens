"""Tests for TrustLens Deterministic Threat Detection Rules."""

import pytest

from trustlens_intelligence.detection.engine import DetectionEngine
from trustlens_intelligence.detection.registry import RuleRegistry
from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.evidence import (
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)


def test_openphish_decisive_detection(phishing_site_evidence):
    """OpenPhish match must trigger decisive CRITICAL finding."""
    features = FeatureExtractor().extract(phishing_site_evidence)
    res = DetectionEngine().evaluate(phishing_site_evidence, features)

    assert res.has_decisive_malicious is True
    assert "OPENPHISH_URL_MATCH" in res.decisive_rule_codes
    assert any(f.code == "OPENPHISH_URL_MATCH" and f.points == 100 for f in res.findings)


def test_urlhaus_online_decisive_detection(malware_site_evidence):
    """URLhaus online match must trigger decisive CRITICAL finding."""
    features = FeatureExtractor().extract(malware_site_evidence)
    res = DetectionEngine().evaluate(malware_site_evidence, features)

    assert res.has_decisive_malicious is True
    assert "URLHAUS_ONLINE_URL_MATCH" in res.decisive_rule_codes


def test_urlhaus_historical_is_additive_not_decisive():
    """Historical URLhaus match (offline) is additive (25 pts), not decisive."""
    ev = ScanEvidence(
        original_url="http://historical-malware.example",
        threat_intelligence=ThreatIntelEvidence(
            urlhaus_match=True,
            urlhaus_status="match",
            urlhaus_url_status="offline",
        ),
    )
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    assert res.has_decisive_malicious is False
    assert any(f.code == "URLHAUS_HISTORICAL_URL_MATCH" and f.points == 25 for f in res.findings)


def test_certificate_rules_trigger():
    """Invalid chain, hostname mismatch, and expired certificate must trigger respective rules."""
    ev = ScanEvidence(
        original_url="https://bad-cert.example.com",
        scheme="https",
        tls=TlsCertificateEvidence(
            chain_valid=False,
            hostname_match=False,
            is_expired=True,
            days_until_expiry=-10,
            protocol_version="TLSv1.0",
        ),
    )
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    codes = {f.code for f in res.findings}
    assert "CERT_CHAIN_INVALID" in codes
    assert "CERT_HOSTNAME_MISMATCH" in codes
    assert "CERT_EXPIRED" in codes
    assert "TLS_LEGACY_PROTOCOL" in codes


def test_cookie_rules_point_capping():
    """Insecure cookies must trigger findings with configured point caps."""
    # 5 cookies missing Secure (3 pts each, max cap = 6)
    cookies = [
        CookieEvidence(name=f"c_{i}", secure=False, httponly=False, samesite=None)
        for i in range(5)
    ]
    ev = ScanEvidence(
        original_url="https://example.com",
        scheme="https",
        http=HttpEvidence(status_code=200, cookies=cookies),
        tls=TlsCertificateEvidence(valid=True),
    )
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    secure_finding = next((f for f in res.findings if f.code == "COOKIE_SECURE_MISSING"), None)
    httponly_finding = next((f for f in res.findings if f.code == "COOKIE_HTTPONLY_MISSING"), None)
    samesite_finding = next((f for f in res.findings if f.code == "COOKIE_SAMESITE_MISSING"), None)

    assert secure_finding is not None
    assert secure_finding.points == 6  # Capped at 6
    assert httponly_finding is not None
    assert httponly_finding.points == 4  # Capped at 4
    assert samesite_finding is not None
    assert samesite_finding.points == 4  # Capped at 4


def test_recently_registered_domain_rule():
    """Domains <= 30 days old trigger DOMAIN_RECENTLY_REGISTERED."""
    ev = ScanEvidence(
        original_url="https://new-domain.com",
        domain_intelligence=DomainIntelligenceEvidence(domain_age_days=14),
    )
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    assert any(f.code == "DOMAIN_RECENTLY_REGISTERED" and f.points == 15 for f in res.findings)


def test_rule_registry_toggle():
    """Rules can be dynamically disabled and enabled in the registry."""
    registry = RuleRegistry()
    assert len(registry) > 15
    registry.disable("HSTS_MISSING")
    enabled_codes = {r.code for r in registry.get_enabled_rules()}
    assert "HSTS_MISSING" not in enabled_codes
    registry.enable("HSTS_MISSING")
    assert "HSTS_MISSING" in {r.code for r in registry.get_enabled_rules()}


def test_suspicious_userinfo_rule():
    """Embedded credentials/userinfo triggers SUSPICIOUS_USERINFO rule."""
    ev = ScanEvidence(original_url="http://victim:pass123@evil-host.com/login")
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    userinfo_finding = next((f for f in res.findings if f.code == "SUSPICIOUS_USERINFO"), None)
    assert userinfo_finding is not None
    assert userinfo_finding.points == 15
    assert userinfo_finding.severity == "high"


def test_http_no_https_redirect_requires_http_evidence():
    """When HTTP observation is absent (None), do not false-positive trigger HTTP_NO_HTTPS_REDIRECT."""
    ev = ScanEvidence(
        original_url="http://unreachable-host.com",
        scheme="http",
        http=None,  # Scan failed or unreachable
    )
    features = FeatureExtractor().extract(ev)
    res = DetectionEngine().evaluate(ev, features)

    codes = {f.code for f in res.findings}
    assert "HTTP_NO_HTTPS_REDIRECT" not in codes


