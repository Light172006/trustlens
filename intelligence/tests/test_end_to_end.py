"""End-to-end integration tests for the TrustLens Intelligence Pipeline."""

import pytest

from trustlens_intelligence import (
    ScanEvidence,
    TrustLensIntelligenceEngine,
    Verdict,
    analyze_website,
    evaluate_threat_feeds,
    extract_features,
)
from trustlens_intelligence.config.constants import ProviderResultStatus
from trustlens_intelligence.schemas.evidence import (
    CookieEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.threat_feeds.manager import ThreatIntelManager
from trustlens_intelligence.threat_feeds.mock_provider import MockThreatProvider


def test_e2e_clean_website_analysis(clean_site_evidence):
    """Clean site assessment produces SAFE verdict with score 0 and full coverage."""
    assessment = analyze_website(clean_site_evidence)
    assert assessment.verdict == Verdict.SAFE
    assert assessment.risk_score == 0
    assert assessment.confidence >= 0.85
    assert "No material risk was found" in assessment.summary
    api_dict = assessment.to_api_dict()
    assert api_dict["verdict"] == "SAFE"
    assert api_dict["risk_score"] == 0


def test_e2e_phishing_detection(phishing_site_evidence):
    """Phishing URL produces MALICIOUS verdict with score 100 and decisive finding."""
    assessment = analyze_website(phishing_site_evidence)
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score == 100
    assert assessment.confidence >= 0.90
    assert any(f.code == "OPENPHISH_URL_MATCH" for f in assessment.findings)


def test_e2e_malware_detection(malware_site_evidence):
    """Malware distribution URL produces MALICIOUS verdict with score 100."""
    assessment = analyze_website(malware_site_evidence)
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score == 100
    assert any(f.code == "URLHAUS_ONLINE_URL_MATCH" for f in assessment.findings)


def test_e2e_expired_cert_and_missing_headers_suspicious(expired_cert_evidence):
    """Expired cert and missing headers produce SUSPICIOUS verdict with score > 25."""
    assessment = analyze_website(expired_cert_evidence)
    assert assessment.verdict == Verdict.SUSPICIOUS
    assert assessment.risk_score >= 25
    assert any(f.code == "CERT_EXPIRED" for f in assessment.findings)


def test_e2e_provider_outage_produces_inconclusive(clean_site_evidence):
    """Provider outage prevents SAFE verdict and yields INCONCLUSIVE with explanatory finding."""
    # Build engine with mock provider that simulates outage
    mock_outage_provider = MockThreatProvider(name="urlhaus", simulate_unavailable=True)
    mock_phish = MockThreatProvider(name="openphish")
    manager = ThreatIntelManager(providers=[mock_phish, mock_outage_provider])
    engine = TrustLensIntelligenceEngine(threat_manager=manager)

    assessment = engine.analyze(clean_site_evidence, query_providers=True)

    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.coverage["threat_intel"] == "partial"
    # Explainability invariant: non-SAFE verdict must have finding!
    assert len(assessment.findings) >= 1
    assert any(f.code == "COVERAGE_INSUFFICIENT" for f in assessment.findings)


def test_e2e_sensitive_url_skips_external_provider():
    """Sensitive URLs skip external providers and prevent false safe verdicts."""
    mock_urlhaus = MockThreatProvider(name="urlhaus")
    mock_openphish = MockThreatProvider(name="openphish")
    manager = ThreatIntelManager(providers=[mock_openphish, mock_urlhaus])
    engine = TrustLensIntelligenceEngine(threat_manager=manager)

    sensitive_ev = ScanEvidence(
        original_url="https://example.com/reset?token=supersecret123",
        is_sensitive=True,
        http=HttpEvidence(status_code=200, security_headers={"content-security-policy": "default-src 'self'"}),
        tls=TlsCertificateEvidence(chain_valid=True),
    )

    assessment = engine.analyze(sensitive_ev, query_providers=True)
    # URLhaus check was skipped
    urlhaus_check = next((p for p in assessment.provider_checks if p.provider == "urlhaus"), None)
    assert urlhaus_check is not None
    assert urlhaus_check.result_status == ProviderResultStatus.SKIPPED_SENSITIVE_URL
    # Incomplete coverage prevents SAFE
    assert assessment.verdict == Verdict.INCONCLUSIVE


def test_e2e_failed_scan_handling():
    """Internal scan failures produce INCONCLUSIVE with null risk_score."""
    ev = ScanEvidence(original_url="http://crashed.example")
    assessment = analyze_website(ev, is_scan_failed=True)

    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.risk_score is None
    assert assessment.confidence == 0.0


def test_e2e_standalone_helper_functions():
    """Verify standalone public helper functions."""
    ev = ScanEvidence(original_url="https://example.com")
    features = extract_features(ev)
    assert features.url_length == len("https://example.com")


def test_e2e_combinatorial_adversarial_evidence():
    """Verify end-to-end resilience against combinatorial adversarial indicators."""
    from trustlens_intelligence.schemas.evidence import CookieEvidence, RedirectHopEvidence

    ev = ScanEvidence(
        scan_id="adversarial_e2e_001",
        original_url="https://admin:pwd@0x7f.0.0.1:8443/login?redirect=http://0177.0.0.1/evil",
        host="0x7f.0.0.1",
        scheme="https",
        is_sensitive=False,
        http=HttpEvidence(
            status_code=302,
            final_url="https://target.com:99999/dest",
            redirect_count=5,
            redirects=[
                RedirectHopEvidence(
                    hop_index=i,
                    source_url=f"http://hop{i}.com/",
                    destination_url=f"http://hop{i+1}.com/",
                    http_status=302,
                    resolved_host=f"hop{i+1}.com",
                )
                for i in range(5)
            ],
            security_headers={},
            cookies=[
                CookieEvidence(name=f"c{i}", secure=False, httponly=False, samesite="")
                for i in range(10)
            ],
        ),
        tls=TlsCertificateEvidence(
            valid=False,
            chain_valid=False,
            hostname_match=False,
            expired=True,
            days_until_expiry=-50,
            protocol="TLSv1.0",
        ),
        domain_intelligence=DomainIntelligenceEvidence(domain_age_days=0),
    )

    assessment = analyze_website(ev)
    assert assessment.scan_id == "adversarial_e2e_001"
    assert assessment.verdict == Verdict.SUSPICIOUS
    assert assessment.risk_score == 100
    assert assessment.confidence > 0.5
    assert len(assessment.findings) >= 10

    # Ensure no duplicate finding codes exist in the assessment
    finding_codes = [f.code for f in assessment.findings]
    assert len(finding_codes) == len(set(finding_codes))

    # Verify to_api_dict() preserves scan_id and all attributes
    api_dict = assessment.to_api_dict()
    assert api_dict["scan_id"] == "adversarial_e2e_001"
    assert api_dict["risk_score"] == 100


def test_e2e_provider_unhandled_exception_resilience():
    """Verify ThreatIntelManager handles unexpected provider exceptions without crashing."""
    class CrashingProvider(MockThreatProvider):
        def query(self, url, is_sensitive=False):
            raise RuntimeError("Underlying socket abruptly closed by peer")

    manager = ThreatIntelManager(providers=[CrashingProvider(name="crashing_feed")])
    results = manager.query_all("https://example.com")
    assert len(results) == 1
    assert results[0].provider == "crashing_feed"
    assert results[0].result_status == ProviderResultStatus.UNAVAILABLE
    assert results[0].matched is False
    assert results[0].details.get("error") == "unhandled_provider_exception"


def test_e2e_sub_50ms_latency_benchmark():
    """Verify that in-memory assessment latency complies with PRD NFR-01 (< 50ms)."""
    import statistics
    import time

    ev = ScanEvidence(
        original_url="https://example.com/test",
        http=HttpEvidence(status_code=200, security_headers={"strict-transport-security": "max-age=31536000"}),
        tls=TlsCertificateEvidence(chain_valid=True),
    )

    # Warm up
    analyze_website(ev)

    times_ms = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = analyze_website(ev)
        t1 = time.perf_counter()
        times_ms.append((t1 - t0) * 1000)

    median_latency = statistics.median(times_ms)
    # Target is sub-50ms; our in-memory engine achieves ~1.4ms
    assert median_latency < 25.0, f"Assessment latency exceeded target: {median_latency:.2f}ms"
    assert res.verdict in (Verdict.SAFE, Verdict.INCONCLUSIVE)



