"""
TrustLens Intelligence — Cross-Module Consistency & Invariant Stress Tests (Phase 8)
Verifies semantic separation and alignment across:
1. Threat Analysis (trustlens_intelligence)
2. Collaborative Intelligence (collaborative_intelligence)
3. Certificate Analyzer (certificate_analyzer)
4. Web Security Analyzer (web_security_analysis)
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict
from unittest.mock import AsyncMock, patch
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "certificate_analyzer" / "src"))
sys.path.insert(0, str(BASE_DIR / "certificate_dataset" / "src"))
sys.path.insert(0, str(BASE_DIR / "collaborative_intelligence"))
sys.path.insert(0, str(BASE_DIR / "web_security_analysis"))
sys.path.insert(0, str(BASE_DIR / "web_security_analysis" / "analyzer"))
sys.path.insert(0, str(BASE_DIR / "web_security_analysis" / "training"))

from trustlens_intelligence.api import analyze_website
from trustlens_intelligence.config.constants import Verdict as ThreatVerdict
from trustlens_intelligence.schemas.evidence import (
    ScanEvidence as ThreatScanEvidence,
    HttpEvidence,
    TlsCertificateEvidence,
    ThreatIntelEvidence,
    CommunityIntelligenceEvidence,
)
from certificate_analyzer.engine.analyzer import CertificateAnalyzerEngine
from certificate_analyzer.constants import CertificateVerdict
from collaborative_intelligence.service import CollaborativeIntelligenceEngine
from collaborative_intelligence.corroboration import CorroborationEngine
from collaborative_intelligence.models import CommunityReportInput, ReporterMetadata, EvidenceItem
from collaborative_intelligence.enums import ThreatCategory, EvidenceType, CorroborationLevel
from analyzer.engine import WebSecurityAnalyzer


# ==============================================================================
# Invariant 1: Valid TLS + Confirmed Phishing Indicator
# A website with valid cryptography can still be an active malicious phishing site.
# Threat Analysis must flag MALICIOUS, while Web Security evaluates transport as valid.
# ==============================================================================

def test_cross_module_valid_tls_with_confirmed_phishing():
    url = "https://phishing-site-with-letsencrypt.com/login"

    # 1. Threat Analysis: Decisive Threat Match
    threat_ev = ThreatScanEvidence(
        original_url=url,
        canonical_url=url,
        tls=TlsCertificateEvidence(valid=True, chain_valid=True, hostname_match=True, days_until_expiry=60),
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=True,
            openphish_status="match",
        ),
    )
    threat_assessment = analyze_website(threat_ev)
    assert threat_assessment.verdict == ThreatVerdict.MALICIOUS
    assert threat_assessment.risk_score == 100

    # 2. Web Security Analyzer: Clean Transport Observation
    web_features = {
        "normalized_domain": "phishing-site-with-letsencrypt.com",
        "registrable_domain": "phishing-site-with-letsencrypt.com",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.3",
        "tls_cert_valid": True,
        "tls_cert_expired": False,
        "tls_cert_remaining_days": 60,
        "tls_cert_is_self_signed": False,
        "tls_cert_hostname_match": True,
        "header_hsts_present": True,
        "header_hsts_max_age": 31536000,
        "header_csp_present": True,
        "header_xfo_present": True,
        "header_xcto_present": True,
        "header_referrer_policy_present": True,
        "cookie_count": 0,
        "redirect_count": 0,
        "https_downgrade": False,
        "collection_status": "SUCCESS",
    }
    web_analyzer = WebSecurityAnalyzer()
    from unittest.mock import AsyncMock, patch
    with patch.object(web_analyzer.extractor, "extract_features", new_callable=AsyncMock) as mock_extract:
        mock_extract.return_value = web_features
        web_report = asyncio.run(web_analyzer.analyze_async(url))

    # Invariant: Web Security analyzes technical transport, NOT domain reputation
    assert web_report.posture == "GOOD"
    # Threat Analysis identifies the malicious intent independently
    assert threat_assessment.verdict == ThreatVerdict.MALICIOUS


# ==============================================================================
# Invariant 2: Benign Website with Expired Certificate
# Poor transport configuration does not automatically classify a site as MALICIOUS.
# ==============================================================================

def test_cross_module_expired_tls_on_benign_site():
    url = "https://misconfigured-blog.org"

    threat_ev = ThreatScanEvidence(
        original_url=url,
        canonical_url=url,
        tls=TlsCertificateEvidence(valid=False, chain_valid=False, hostname_match=True, is_expired=True, days_until_expiry=-10),
        threat_intelligence=ThreatIntelEvidence(openphish_match=False, urlhaus_match=False),
    )
    threat_assessment = analyze_website(threat_ev)
    # Misconfiguration alone produces SUSPICIOUS (points added for expired cert), NOT MALICIOUS
    assert threat_assessment.verdict == ThreatVerdict.SUSPICIOUS
    assert threat_assessment.risk_score < 100

    # Web Security Analyzer correctly classifies posture as POOR due to critical TLS failure
    web_features = {
        "normalized_domain": "misconfigured-blog.org",
        "registrable_domain": "misconfigured-blog.org",
        "domain_resolved": True,
        "dns_ipv4_addresses": ["93.184.216.34"],
        "http_available": True,
        "https_available": True,
        "tls_supported": True,
        "tls_version": "TLSv1.2",
        "tls_cert_expired": True,
        "tls_cert_not_after": "2024-01-01T00:00:00Z",
        "tls_cert_remaining_days": -10,
        "tls_cert_is_self_signed": False,
        "tls_cert_hostname_match": True,
        "header_hsts_present": False,
        "header_csp_present": False,
        "header_xfo_present": False,
        "header_xcto_present": False,
        "cookie_count": 0,
        "redirect_count": 0,
        "https_downgrade": False,
        "collection_status": "SUCCESS",
    }
    web_analyzer = WebSecurityAnalyzer()
    with patch.object(web_analyzer.extractor, "extract_features", new_callable=AsyncMock) as mock_extract:
        mock_extract.return_value = web_features
        web_report = asyncio.run(web_analyzer.analyze_async(url))

    assert web_report.posture == "POOR"
    assert any(f.finding_id == "TLS-CERT-EXPIRED" and f.severity == "CRITICAL" for f in web_report.findings)


# ==============================================================================
# Invariant 3: Community Evidence Separation
# Community reports do not fabricate technical findings (e.g. missing HSTS or broken cert).
# ==============================================================================

def test_cross_module_community_evidence_separation():
    url = "https://community-reported.net"

    threat_ev = ThreatScanEvidence(
        original_url=url,
        canonical_url=url,
        tls=TlsCertificateEvidence(valid=True, chain_valid=True, hostname_match=True, days_until_expiry=90),
        http=HttpEvidence(status_code=200, security_headers={"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'"}),
        community_intelligence=CommunityIntelligenceEvidence(
            confirmed_report_count=2,
            distinct_reporter_count=2,
            reports=[{"reporter_id": "r1"}, {"reporter_id": "r2"}],
        ),
    )
    threat_assessment = analyze_website(threat_ev)
    assert threat_assessment.verdict == ThreatVerdict.MALICIOUS

    # Verify that the findings contain the community finding, but NOT spurious TLS or header errors
    finding_codes = {f.code for f in threat_assessment.findings}
    assert "COMMUNITY_CONFIRMED_MALICIOUS" in finding_codes
    assert "CERT_EXPIRED" not in finding_codes
    assert "HSTS_MISSING" not in finding_codes
    assert "CSP_MISSING" not in finding_codes


# ==============================================================================
# Invariant 4: Provider Failure Does Not Produce False SAFE
# If external threat feeds fail, the assessment must be INCONCLUSIVE, not SAFE.
# ==============================================================================

def test_cross_module_provider_failure_inconclusive():
    url = "https://unknown-domain.io"

    threat_ev = ThreatScanEvidence(
        original_url=url,
        canonical_url=url,
        tls=TlsCertificateEvidence(valid=True, chain_valid=True, hostname_match=True, days_until_expiry=120),
        threat_intelligence=ThreatIntelEvidence(
            openphish_status="unavailable",
            urlhaus_status="unavailable",
        ),
    )
    threat_assessment = analyze_website(threat_ev)
    assert threat_assessment.verdict == ThreatVerdict.INCONCLUSIVE
    assert any(f.code == "COVERAGE_INSUFFICIENT" for f in threat_assessment.findings)


# ==============================================================================
# Invariant 5: Sybil Attack Rejection in Collaborative Intelligence
# Multiple accounts sharing identical evidence items cannot create decisive high corroboration.
# ==============================================================================

def test_cross_module_sybil_abuse_resilience():
    corrob_engine = CorroborationEngine()
    now = datetime.now(timezone.utc)

    # 4 distinct accounts submitting the exact same screenshot hash and payload
    shared_evidence = [
        EvidenceItem(
            evidence_type=EvidenceType.SCREENSHOT,
            source="community_upload",
            description="Phishing kit screenshot hash",
            fingerprint="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    ]

    reports = [
        CommunityReportInput(
            original_url="https://sybil-attack-target.com",
            category=ThreatCategory.PHISHING,
            reporter=ReporterMetadata(reporter_id=f"sybil_sockpuppet_{i}"),
            evidence_items=shared_evidence,
            submitted_at=now,
        )
        for i in range(4)
    ]

    corrob = corrob_engine.evaluate_corroboration(reports, reference_time=now)
    # Because accounts share identical evidence, independent reporter count must collapse
    assert corrob.independent_reporter_count < 4
    # Cannot achieve HIGH corroboration under Sybil conditions
    assert corrob.corroboration_level != CorroborationLevel.HIGH
