"""Unit tests for confirmed threat indicator lifecycle, scope enforcement, and scan matching."""

from datetime import datetime, timedelta, timezone
import pytest

from collaborative_intelligence.enums import (
    CorroborationLevel,
    IndicatorScope,
    IndicatorStatus,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    ConfirmedIndicator,
    ConfirmedIndicatorMatch,
)
from collaborative_intelligence.indicators import (
    IndicatorMatcher,
    evaluate_indicator_status,
)
from collaborative_intelligence.service import CollaborativeIntelligenceEngine


@pytest.fixture
def matcher():
    return IndicatorMatcher()


@pytest.fixture
def base_confirmed_url_indicator():
    now = datetime.now(timezone.utc)
    return ConfirmedIndicator(
        indicator_id="ind_exact_1",
        indicator_value="https://phish.target.com/login",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=90),
        corroboration_level=CorroborationLevel.HIGH,
        moderator_id="mod_admin_1",
        evidence_summary="Verified credential harvesting endpoint.",
    )


@pytest.fixture
def base_confirmed_host_indicator():
    now = datetime.now(timezone.utc)
    return ConfirmedIndicator(
        indicator_id="ind_host_1",
        indicator_value="malware.distribution-center.net",
        scope=IndicatorScope.HOST,
        threat_category=ThreatCategory.MALWARE,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=90),
        corroboration_level=CorroborationLevel.HIGH,
        moderator_id="mod_admin_2",
        evidence_summary="Dedicated malware payload distribution host.",
    )


@pytest.fixture
def base_confirmed_domain_indicator():
    now = datetime.now(timezone.utc)
    return ConfirmedIndicator(
        indicator_id="ind_domain_1",
        indicator_value="wildcard-phish-campaign.top",
        scope=IndicatorScope.DOMAIN,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=90),
        corroboration_level=CorroborationLevel.HIGH,
        moderator_id="mod_admin_3",
        evidence_summary="Domain with wildcard DNS configured for mass phishing campaign.",
    )


def test_exact_url_scope_matching(matcher, base_confirmed_url_indicator):
    """Target URL matching exact indicator matches; different path on same host does NOT match."""
    # 1. Matching exact URL (even with different casing/port normalization)
    target_match = "HTTPS://PHISH.TARGET.COM:443/login"
    res1 = matcher.match(target_match, [base_confirmed_url_indicator])
    assert res1.matched is True
    assert res1.is_active is True
    assert res1.matched_scope == IndicatorScope.EXACT_URL
    assert res1.indicator.indicator_id == "ind_exact_1"

    # 2. Different path on same host MUST NOT match EXACT_URL scoped indicator
    target_different_path = "https://phish.target.com/about"
    res2 = matcher.match(target_different_path, [base_confirmed_url_indicator])
    assert res2.matched is False
    assert res2.indicator is None


def test_host_scope_matching(matcher, base_confirmed_host_indicator):
    """HOST-scoped indicator matches any path on that host, but NOT different subdomains."""
    # 1. Any path on matching host matches
    target_url = "http://malware.distribution-center.net/payload.exe?v=1"
    res1 = matcher.match(target_url, [base_confirmed_host_indicator])
    assert res1.matched is True
    assert res1.is_active is True
    assert res1.matched_scope == IndicatorScope.HOST
    assert res1.indicator.indicator_id == "ind_host_1"

    # 2. Different subdomain on same apex domain MUST NOT match HOST-scoped indicator
    diff_subdomain = "http://legit.distribution-center.net/info"
    res2 = matcher.match(diff_subdomain, [base_confirmed_host_indicator])
    assert res2.matched is False


def test_domain_scope_matching(matcher, base_confirmed_domain_indicator):
    """DOMAIN-scoped indicator matches all subdomains on that domain."""
    target_sub = "https://bank-login.secure.wildcard-phish-campaign.top/portal"
    res = matcher.match(target_sub, [base_confirmed_domain_indicator])
    assert res.matched is True
    assert res.is_active is True
    assert res.matched_scope == IndicatorScope.DOMAIN
    assert res.indicator.indicator_id == "ind_domain_1"


def test_scope_precedence_exact_over_host_over_domain(
    matcher,
    base_confirmed_url_indicator,
    base_confirmed_host_indicator,
    base_confirmed_domain_indicator,
):
    """Exact URL match takes precedence over host and domain scopes."""
    now = datetime.now(timezone.utc)
    # Create indicators at exact, host, and domain scopes for the same URL target
    exact_ind = ConfirmedIndicator(
        indicator_id="ind_exact",
        indicator_value="https://test.bad-domain.com/phish",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=30),
        moderator_id="mod",
    )
    host_ind = ConfirmedIndicator(
        indicator_id="ind_host",
        indicator_value="test.bad-domain.com",
        scope=IndicatorScope.HOST,
        threat_category=ThreatCategory.MALWARE,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=30),
        moderator_id="mod",
    )

    # Query target that matches both
    res = matcher.match("https://test.bad-domain.com/phish", [host_ind, exact_ind])
    assert res.matched is True
    assert res.matched_scope == IndicatorScope.EXACT_URL
    assert res.indicator.indicator_id == "ind_exact"


def test_expired_indicator_exclusion(matcher, base_confirmed_url_indicator):
    """Expired indicators are excluded from active threat matching."""
    now = datetime.now(timezone.utc)
    expired_ind = ConfirmedIndicator(
        indicator_id="ind_expired",
        indicator_value="https://phish.target.com/login",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now - timedelta(days=100),
        expires_at=now - timedelta(days=10),
        moderator_id="mod",
    )

    res = matcher.match("https://phish.target.com/login", [expired_ind], current_time=now)
    assert res.matched is False
    assert res.is_active is False
    assert "EXPIRED" in res.explanation


def test_revoked_indicator_exclusion(matcher):
    """Revoked indicators are excluded from active threat matching."""
    now = datetime.now(timezone.utc)
    revoked_ind = ConfirmedIndicator(
        indicator_id="ind_revoked",
        indicator_value="https://phish.target.com/login",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now - timedelta(days=20),
        expires_at=now + timedelta(days=70),
        revoked_at=now - timedelta(days=2),
        moderator_id="mod",
    )

    res = matcher.match("https://phish.target.com/login", [revoked_ind], current_time=now)
    assert res.matched is False
    assert res.is_active is False
    assert "REVOKED" in res.explanation


def test_disputed_indicator_exclusion(matcher):
    """Disputed indicators are excluded from active threat matching pending investigation."""
    now = datetime.now(timezone.utc)
    disputed_ind = ConfirmedIndicator(
        indicator_id="ind_disputed",
        indicator_value="https://phish.target.com/login",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now - timedelta(days=20),
        expires_at=now + timedelta(days=70),
        disputed_at=now - timedelta(days=1),
        moderator_id="mod",
    )

    res = matcher.match("https://phish.target.com/login", [disputed_ind], current_time=now)
    assert res.matched is False
    assert res.is_active is False
    assert "DISPUTED" in res.explanation


def test_unconfirmed_report_cannot_match_as_confirmed_threat():
    """Unconfirmed indicators with status UNCONFIRMED never match active intelligence."""
    matcher = IndicatorMatcher()
    now = datetime.now(timezone.utc)
    unconfirmed = ConfirmedIndicator(
        indicator_id="ind_unconf",
        indicator_value="https://phish.target.com/login",
        scope=IndicatorScope.EXACT_URL,
        status=IndicatorStatus.UNCONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=30),
        moderator_id="system",
    )

    res = matcher.match("https://phish.target.com/login", [unconfirmed], current_time=now)
    assert res.matched is False
    assert res.is_active is False


def test_end_to_end_engine_service_orchestration():
    """Verify high-level CollaborativeIntelligenceEngine orchestrates all pipelines seamlessly."""
    engine = CollaborativeIntelligenceEngine()
    now = datetime.now(timezone.utc)

    # 1. Submit initial report
    from collaborative_intelligence.models import CommunityReportInput, EvidenceItem, ReporterMetadata
    from collaborative_intelligence.enums import EvidenceType

    report1 = CommunityReportInput(
        submission_id="sub_e2e_1",
        original_url="https://secure-credential-phish.net/login?token=abc",
        category=ThreatCategory.PHISHING,
        description="Impersonating PayPal login with credential drop.",
        evidence_items=[
            EvidenceItem(
                evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
                source="scanner",
                description="Form action points to /drop.php stealing credentials.",
                is_verified=True,
            )
        ],
        submitted_at=now,
        reporter=ReporterMetadata(
            reporter_id="analyst_1",
            account_age_days=120,
            previous_accepted_reports=15,
            previous_rejected_reports=1,
            is_trusted=True,
        ),
    )

    eval_result = engine.evaluate_report(report1)
    assert eval_result.validation.is_valid is True
    assert eval_result.canonical_url == "https://secure-credential-phish.net/login?token=abc"
    assert eval_result.deduplication.is_duplicate is False
    assert eval_result.moderation_recommendation.requires_human_approval is True

    # 2. Submit duplicate report
    report2 = CommunityReportInput(
        submission_id="sub_e2e_2",
        original_url="https://SECURE-credential-phish.net/login?token=abc#frag",
        category=ThreatCategory.PHISHING,
        reporter=ReporterMetadata(reporter_id="analyst_2"),
    )
    eval_dup = engine.evaluate_report(report2, existing_reports=[report1])
    assert eval_dup.deduplication.is_duplicate is True
    assert eval_dup.moderation_recommendation.recommended_report_status.value == "DUPLICATE"

    # 3. Test engine helper delegation methods
    corrob_res = engine.evaluate_corroboration([report1])
    assert corrob_res.independent_reporter_count == 1

    dedup_res = engine.find_duplicate_reports(report2, [report1])
    assert dedup_res.is_duplicate is True

    mod_res = engine.recommend_moderation_action(
        report1, eval_result.validation, dedup_res, corrob_res
    )
    assert mod_res.requires_human_approval is True

    # 4. Confirmed indicator lifecycle and matching
    ind = ConfirmedIndicator(
        indicator_id="ind_e2e_conf",
        indicator_value="https://secure-credential-phish.net/login?token=abc",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.CONFIRMED,
        confirmed_at=now,
        expires_at=now + timedelta(days=60),
        moderator_id="admin_mod",
    )
    status = engine.evaluate_indicator_lifecycle(ind)
    assert status == IndicatorStatus.CONFIRMED

    match_res = engine.match_confirmed_indicator(
        "https://secure-credential-phish.net/login?token=abc", [ind]
    )
    assert match_res.matched is True
    assert match_res.is_active is True
