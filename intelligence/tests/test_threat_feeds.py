"""Tests for TrustLens Threat Intelligence Provider Adapters and Manager."""

from datetime import datetime, timedelta, timezone
import pytest

from trustlens_intelligence.config.constants import LayerCoverage, ProviderResultStatus
from trustlens_intelligence.threat_feeds.community import CommunityIntelProvider
from trustlens_intelligence.threat_feeds.manager import ThreatIntelManager
from trustlens_intelligence.threat_feeds.mock_provider import MockThreatProvider
from trustlens_intelligence.threat_feeds.openphish import OpenPhishProvider, canonicalize_url
from trustlens_intelligence.threat_feeds.urlhaus import URLhausProvider


def test_openphish_exact_matching_and_normalization():
    """OpenPhish matches exact canonical URLs in local cache."""
    provider = OpenPhishProvider(
        initial_indicators={"http://phish.example.com/login?u=1#frag"}
    )
    # Query with slightly different fragment/spacing
    res = provider.query("http://phish.example.com/login?u=1")
    assert res.matched is True
    assert res.result_status == ProviderResultStatus.MATCH

    # Non-matching URL
    res_clean = provider.query("http://clean.example.com")
    assert res_clean.matched is False
    assert res_clean.result_status == ProviderResultStatus.NO_MATCH


def test_openphish_stale_cache_behavior():
    """A stale feed (>13h old) must not produce a clean NO_MATCH."""
    provider = OpenPhishProvider(initial_indicators={"http://old-threat.example/bin"})
    # Manually backdate sync time to simulate stale feed
    provider.last_successful_sync = datetime.now(timezone.utc) - timedelta(hours=14)
    assert provider.is_stale() is True

    # A non-matching query on stale cache returns STALE_CACHE, never clean NO_MATCH
    res = provider.query("http://unknown.example.com")
    assert res.result_status == ProviderResultStatus.STALE_CACHE
    assert res.matched is False


def test_urlhaus_sensitive_url_skip():
    """Sensitive URLs must be skipped and never transmitted externally."""
    provider = URLhausProvider()
    res = provider.query("https://example.com/reset?token=secret123", is_sensitive=True)
    assert res.result_status == ProviderResultStatus.SKIPPED_SENSITIVE_URL
    assert res.matched is False


def test_community_intelligence_threshold():
    """Community reports require at least 2 distinct moderator-confirmed reporters to be decisive."""
    provider = CommunityIntelProvider()
    url = "http://reported.example.com"

    # 1 report: not decisive
    provider.register_report(url, reporter_id="user_1", status="confirmed")
    res1 = provider.query(url)
    assert res1.matched is False
    assert res1.details["is_decisive"] is False

    # 2 reports from same user: still not decisive (distinct reporter requirement)
    provider.register_report(url, reporter_id="user_1", status="confirmed")
    res2 = provider.query(url)
    assert res2.matched is False

    # 2 reports from 2 distinct users: decisive match!
    provider.register_report(url, reporter_id="user_2", status="confirmed")
    res3 = provider.query(url)
    assert res3.matched is True
    assert res3.details["is_decisive"] is True


def test_threat_intel_manager_caching_and_coverage():
    """Verify ThreatIntelManager caching and layer coverage evaluation."""
    p_phish = MockThreatProvider(name="openphish")
    p_urlhaus = MockThreatProvider(name="urlhaus")
    manager = ThreatIntelManager(providers=[p_phish, p_urlhaus])

    results = manager.query_all("https://example.com")
    assert len(results) == 2
    coverage = manager.evaluate_threat_coverage(results)
    assert coverage == LayerCoverage.COMPLETE

    # Simulate URLhaus failure
    p_urlhaus.simulate_unavailable = True
    manager.clear_cache()
    results_fail = manager.query_all("https://example.com")
    coverage_fail = manager.evaluate_threat_coverage(results_fail)
    # Unavailable provider prevents complete coverage!
    assert coverage_fail == LayerCoverage.PARTIAL


def test_urlhaus_http_mock_responses():
    """Test URLhaus provider with mocked HTTP responses."""
    import httpx

    # 1. Online malware match
    def mock_online_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["Mirai", "ELF"],
                "date_added": "2026-11-01",
            },
        )

    client_online = httpx.Client(transport=httpx.MockTransport(mock_online_handler))
    provider_online = URLhausProvider(http_client=client_online)
    res_online = provider_online.query("http://malware.example/bin")
    assert res_online.matched is True
    assert res_online.result_status == ProviderResultStatus.MATCH
    assert res_online.details["url_status"] == "online"

    # 2. No results (clean)
    def mock_clean_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_results"})

    client_clean = httpx.Client(transport=httpx.MockTransport(mock_clean_handler))
    provider_clean = URLhausProvider(http_client=client_clean)
    res_clean = provider_clean.query("http://clean.example/page")
    assert res_clean.matched is False
    assert res_clean.result_status == ProviderResultStatus.NO_MATCH

    # 3. HTTP 500 error
    def mock_err_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client_err = httpx.Client(transport=httpx.MockTransport(mock_err_handler))
    provider_err = URLhausProvider(http_client=client_err)
    res_err = provider_err.query("http://any.example")
    assert res_err.matched is False
    assert res_err.result_status == ProviderResultStatus.UNAVAILABLE


def test_openphish_sync_feed_mock():
    """Test OpenPhish feed downloading and ingestion with mock transport."""
    import httpx

    feed_content = (
        "# OpenPhish Community Feed\n"
        "http://phish1.example/login\n"
        "http://phish2.example/secure\n"
        "\n"
    )

    def mock_feed_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=feed_content)

    client = httpx.Client(transport=httpx.MockTransport(mock_feed_handler))
    provider = OpenPhishProvider()
    success = provider.sync_feed(client=client)
    assert success is True
    assert provider.is_healthy() is True

    # Test matched URL
    res = provider.query("http://phish1.example/login")
    assert res.matched is True
    assert res.result_status == ProviderResultStatus.MATCH

    # Test failed feed sync
    def mock_fail_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    fail_client = httpx.Client(transport=httpx.MockTransport(mock_fail_handler))
    fail_provider = OpenPhishProvider()
    assert fail_provider.sync_feed(client=fail_client) is False


def test_threat_intel_manager_bounded_cache_eviction():
    """Cache must respect max_cache_size and evict entries when capacity is exceeded."""
    from trustlens_intelligence.config.settings import ThreatFeedSettings

    settings = ThreatFeedSettings(max_cache_size=5, provider_cache_ttl_seconds=3600)
    mock_prov = MockThreatProvider(name="mock")
    manager = ThreatIntelManager(settings=settings, providers=[mock_prov])

    # Insert 10 different URLs into cache
    for i in range(10):
        manager.query_all(f"http://test{i}.example.com", use_cache=True)

    # Cache should never grow unboundedly past max_cache_size
    assert len(manager._cache) <= 5


def test_urlhaus_transient_retry_success():
    """Transient errors (e.g. 503) are retried with exponential backoff and succeed if subsequent attempt passes."""
    import httpx

    attempt_count = 0

    def mock_transient_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            return httpx.Response(503, text="Service Temporarily Unavailable")
        return httpx.Response(200, json={"query_status": "ok", "url_status": "online"})

    client = httpx.Client(transport=httpx.MockTransport(mock_transient_handler))
    provider = URLhausProvider(
        max_retries=2,
        backoff_factor=0.01,  # Fast backoff for offline test
        http_client=client,
    )
    res = provider.query("http://transient-threat.example/malware")
    assert attempt_count == 2
    assert res.matched is True
    assert res.result_status == ProviderResultStatus.MATCH


def test_api_community_provider_check_propagation():
    """Community intelligence reports propagate to assessment.provider_checks."""
    from trustlens_intelligence.api import TrustLensIntelligenceEngine
    from trustlens_intelligence.schemas.evidence import CommunityIntelligenceEvidence, ScanEvidence

    engine = TrustLensIntelligenceEngine()
    ev = ScanEvidence(
        original_url="https://reported-site.example",
        community_intelligence=CommunityIntelligenceEvidence(
            confirmed_report_count=4,
            category_breakdown={"phishing": 4},
        ),
    )
    assessment = engine.analyze(ev, query_providers=False)
    comm_check = next((p for p in assessment.provider_checks if p.provider == "community"), None)
    assert comm_check is not None
    assert comm_check.matched is True
    assert comm_check.result_status == ProviderResultStatus.MATCH


def test_threat_intel_manager_concurrent_thread_safety():
    """Verify thread-safety of ThreatIntelManager in-memory cache under high concurrency."""
    from concurrent.futures import ThreadPoolExecutor
    from trustlens_intelligence.config.settings import ThreatFeedSettings

    settings = ThreatFeedSettings(max_cache_size=20, provider_cache_ttl_seconds=3600)
    manager = ThreatIntelManager(settings=settings, providers=[MockThreatProvider(name="mock")])

    def worker(worker_id: int):
        for i in range(50):
            url = f"https://concurrent-test-{worker_id}-{i % 10}.example.com/"
            res = manager.query_all(url, use_cache=True)
            assert len(res) == 1

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker, w) for w in range(10)]
        for f in futures:
            f.result()

    assert len(manager._cache) <= settings.max_cache_size



