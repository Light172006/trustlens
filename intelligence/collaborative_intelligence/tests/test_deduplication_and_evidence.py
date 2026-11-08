"""Unit tests for deduplication engine and evidence evaluation layer."""

from datetime import datetime, timezone
import pytest

from collaborative_intelligence.config import DeduplicationConfig, EvidenceEvaluationConfig
from collaborative_intelligence.enums import (
    DeduplicationStrength,
    EvidenceStance,
    EvidenceType,
    ThreatCategory,
)
from collaborative_intelligence.models import (
    CommunityReportInput,
    EvidenceItem,
    ReporterMetadata,
)
from collaborative_intelligence.deduplication import DeduplicationEngine
from collaborative_intelligence.evidence import EvidenceEvaluator, compute_evidence_fingerprint


@pytest.fixture
def base_reporter():
    return ReporterMetadata(
        reporter_id="user_test_alpha",
        account_age_days=90,
        previous_accepted_reports=5,
        previous_rejected_reports=0,
    )


def test_deduplication_exact_raw_match(base_reporter):
    """Exact identical raw URLs are flagged as exact duplicates with safe_to_group=True."""
    engine = DeduplicationEngine()
    rep1 = CommunityReportInput(
        submission_id="sub_1",
        original_url="https://phish.target.com/login",
        reporter=base_reporter,
    )
    rep2 = CommunityReportInput(
        submission_id="sub_2",
        original_url="https://phish.target.com/login",
        reporter=ReporterMetadata(reporter_id="user_test_beta"),
    )

    res = engine.evaluate_duplicates(rep2, [rep1])
    assert res.is_duplicate is True
    assert res.primary_submission_id == "sub_1"
    assert len(res.duplicate_matches) == 1
    assert res.duplicate_matches[0].strength == DeduplicationStrength.EXACT
    assert res.duplicate_matches[0].safe_to_group is True


def test_deduplication_canonical_equivalent(base_reporter):
    """URLs that normalize to the same canonical representation are matched as CANONICAL_EQUIVALENT."""
    engine = DeduplicationEngine()
    rep1 = CommunityReportInput(
        submission_id="sub_1",
        original_url="https://phish.target.com:443/login?b=2&a=1#frag",
        reporter=base_reporter,
    )
    rep2 = CommunityReportInput(
        submission_id="sub_2",
        original_url="https://PHISH.target.com/login?a=1&b=2",
        reporter=ReporterMetadata(reporter_id="user_test_beta"),
    )

    res = engine.evaluate_duplicates(rep2, [rep1])
    assert res.is_duplicate is True
    assert len(res.duplicate_matches) == 1
    assert res.duplicate_matches[0].strength == DeduplicationStrength.CANONICAL_EQUIVALENT
    assert res.duplicate_matches[0].safe_to_group is True


def test_deduplication_path_variants_not_merged(base_reporter):
    """Different paths on the same host are related, but NOT merged as exact duplicates."""
    engine = DeduplicationEngine()
    rep1 = CommunityReportInput(
        submission_id="sub_1",
        original_url="https://example.com/invoice/123",
        reporter=base_reporter,
    )
    rep2 = CommunityReportInput(
        submission_id="sub_2",
        original_url="https://example.com/login/auth",
        reporter=ReporterMetadata(reporter_id="user_test_beta"),
    )

    res = engine.evaluate_duplicates(rep2, [rep1])
    # Not an exact duplicate
    assert res.is_duplicate is False
    assert len(res.duplicate_matches) == 0
    # Flagged as related path variant
    assert len(res.related_matches) == 1
    assert res.related_matches[0].strength == DeduplicationStrength.PATH_VARIANT
    assert res.related_matches[0].safe_to_group is False
    assert "different paths" in res.related_matches[0].explanation


def test_deduplication_subdomain_variants_not_merged(base_reporter):
    """Different subdomains on the same root domain are related, but NOT merged."""
    engine = DeduplicationEngine()
    rep1 = CommunityReportInput(
        submission_id="sub_1",
        original_url="https://legit-sub.example.com/portal",
        reporter=base_reporter,
    )
    rep2 = CommunityReportInput(
        submission_id="sub_2",
        original_url="https://malicious-sub.example.com/portal",
        reporter=ReporterMetadata(reporter_id="user_test_beta"),
    )

    res = engine.evaluate_duplicates(rep2, [rep1])
    assert res.is_duplicate is False
    assert len(res.duplicate_matches) == 0
    assert len(res.related_matches) == 1
    assert res.related_matches[0].strength == DeduplicationStrength.HOST_VARIANT
    assert res.related_matches[0].safe_to_group is False


def test_evidence_fingerprinting_and_duplicate_deduction():
    """Duplicate evidence items are detected by fingerprint and do not inflate score."""
    evaluator = EvidenceEvaluator()

    item1 = EvidenceItem(
        evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
        stance=EvidenceStance.SUPPORTS,
        source="scanner",
        description="Password credential harvester form located at /login.php",
        is_verified=True,
    )
    # Duplicate item with identical description and source
    item2 = EvidenceItem(
        evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
        stance=EvidenceStance.SUPPORTS,
        source="scanner",
        description="Password credential harvester form located at /login.php",
        is_verified=True,
    )

    res_single = evaluator.evaluate([item1])
    res_double = evaluator.evaluate([item1, item2])

    assert len(res_double.distinct_fingerprints) == 1
    assert any("Duplicate evidence detected" in exp for exp in res_double.explanations)
    # Quality score is not inflated by duplicate item
    assert res_double.evidence_quality_score <= res_single.evidence_quality_score


def test_evidence_contradiction_penalizes_score():
    """Contradictory evidence creates explanations and reduces quality score."""
    evaluator = EvidenceEvaluator()

    item_support = EvidenceItem(
        evidence_type=EvidenceType.BROWSER_WARNING,
        stance=EvidenceStance.SUPPORTS,
        source="telemetry",
        description="Browser red screen warning logged for site.",
        is_verified=True,
    )
    item_contradict = EvidenceItem(
        evidence_type=EvidenceType.ANALYZER_FINDING,
        stance=EvidenceStance.CONTRADICTS,
        source="trustlens_scanner",
        description="Legitimate corporate portal with valid EV certificate.",
        is_verified=True,
    )

    res = evaluator.evaluate([item_support, item_contradict])
    assert res.contradicting_count == 1
    assert res.supporting_count == 1
    assert any("Contradictory evidence detected" in exp for exp in res.explanations)
    # Quality score is penalized due to contradiction
    assert res.evidence_quality_score < 0.5


def test_evidence_diversity_score():
    """Evidence across multiple categories achieves higher diversity score."""
    evaluator = EvidenceEvaluator()

    item_phish = EvidenceItem(
        evidence_type=EvidenceType.PHISHING_PAGE_ARTIFACT,
        stance=EvidenceStance.SUPPORTS,
        source="telemetry",
        description="Credential harvesting form on login page.",
        is_verified=True,
    )
    item_dns = EvidenceItem(
        evidence_type=EvidenceType.DNS_OBSERVATION,
        stance=EvidenceStance.SUPPORTS,
        source="resolver",
        description="Fast-flux DNS nameserver cycling detected.",
        is_verified=True,
    )
    item_cert = EvidenceItem(
        evidence_type=EvidenceType.CERTIFICATE_OBSERVATION,
        stance=EvidenceStance.SUPPORTS,
        source="ct_log",
        description="Self-signed untrusted leaf certificate mimicking bank.",
        is_verified=True,
    )

    res_1 = evaluator.evaluate([item_phish])
    res_3 = evaluator.evaluate([item_phish, item_dns, item_cert])

    assert res_1.evidence_diversity_score == pytest.approx(0.3333, abs=0.01)
    assert res_3.evidence_diversity_score == 1.0


def test_unverified_evidence_penalty():
    """Unverified community evidence receives penalty compared to verified sources."""
    evaluator = EvidenceEvaluator()

    item_verified = EvidenceItem(
        evidence_type=EvidenceType.REDIRECT_TRACE,
        stance=EvidenceStance.SUPPORTS,
        source="automated_scanner",
        description="Observed HTTP 302 redirect chain pointing to credential drop.",
        is_verified=True,
    )
    item_unverified = EvidenceItem(
        evidence_type=EvidenceType.REDIRECT_TRACE,
        stance=EvidenceStance.SUPPORTS,
        source="user_upload",
        description="Observed HTTP 302 redirect chain pointing to credential drop.",
        is_verified=False,
    )

    res_v = evaluator.evaluate([item_verified])
    res_u = evaluator.evaluate([item_unverified])

    assert res_u.unverified_count == 1
    assert res_u.evidence_quality_score < res_v.evidence_quality_score

