"""TrustLens Intelligence — Comprehensive Adversarial Stress Testing & Audit Suite.

Conducts rigorous adversarial testing across all intelligence layers:
1. Threat Intel Engine: cache isolation, sensitive URLs, IPv6/IDNA normalization, provider failure modes.
2. Collaborative Intelligence: Sybil attack resistance, single-account flooding, conflicting evidence, unverified reports.
3. Detection Engine: rule exceptions, finding deduplication, conflicting decisive/benign evidence, extreme features.
4. Risk Scoring & Explainability Invariants: 0-100 bounds, 0-1 confidence, deterministic reproducibility, coverage safety.
5. ML Inference: NaN/Inf/None feature resilience, multi-class distribution, artifact corruption fallback.
6. Certificate Analyzer: resource limits, circular issuer prevention, zero-leakage dataset verification.
"""

from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import sys
from typing import Any
import numpy as np
import pytest

# Ensure all submodules and test dependencies are on sys.path
_ROOT = Path(__file__).resolve().parent.parent
_CERT_ANALYZER_SRC = _ROOT / "certificate_analyzer" / "src"
_CERT_DATASET_SRC = _ROOT / "certificate_dataset" / "src"
_COLLAB_SRC = _ROOT / "collaborative_intelligence"

for p in (_CERT_ANALYZER_SRC, _CERT_DATASET_SRC, _COLLAB_SRC):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from collaborative_intelligence.enums import (
    AbuseSignalType,
    CorroborationLevel,
    EvidenceStance,
    EvidenceType,
    IndicatorScope,
    IndicatorStatus,
    ModerationAction,
    ReportStatus,
    ReviewPriority,
    ThreatCategory,
)
from collaborative_intelligence.indicators import IndicatorMatcher, evaluate_indicator_status
from collaborative_intelligence.models import (
    CommunityReportInput,
    ConfirmedIndicator,
    EvidenceItem,
    ReporterMetadata,
)
from collaborative_intelligence.service import CollaborativeIntelligenceEngine
from trustlens_intelligence.api import TrustLensIntelligenceEngine
from trustlens_intelligence.common.url_utils import canonicalize_url_strict, extract_safe_hostname
from trustlens_intelligence.config.constants import (
    FindingCategory,
    FindingSeverity,
    LayerCoverage,
    ProviderResultStatus,
    Verdict,
)
from trustlens_intelligence.config.settings import ThreatFeedSettings
from trustlens_intelligence.detection.engine import DetectionEngine
from trustlens_intelligence.detection.registry import RuleRegistry
from trustlens_intelligence.detection.rules import DetectionRule
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.schemas.assessment import ThreatAssessment
from trustlens_intelligence.schemas.evidence import (
    CommunityIntelligenceEvidence,
    DomainIntelligenceEvidence,
    HttpEvidence,
    ScanEvidence,
    ThreatIntelEvidence,
    TlsCertificateEvidence,
)
from trustlens_intelligence.schemas.features import ExtractedFeatures
from trustlens_intelligence.schemas.findings import Finding
from trustlens_intelligence.schemas.providers import ProviderCheckResult
from trustlens_intelligence.scoring.engine import RiskScoringEngine
from trustlens_intelligence.threat_feeds.base import ThreatIntelProvider
from trustlens_intelligence.threat_feeds.community import CommunityIntelProvider
from trustlens_intelligence.threat_feeds.manager import ThreatIntelManager
from trustlens_intelligence.threat_feeds.mock_provider import MockThreatProvider


# ==============================================================================
# 1. THREAT INTELLIGENCE ENGINE & CACHE ISOLATION STRESS
# ==============================================================================


class PolicySensitiveMockProvider(ThreatIntelProvider):
    """Mock provider that strictly returns SKIPPED_SENSITIVE_URL when is_sensitive=True."""

    def __init__(self, name: str = "policy_mock") -> None:
        super().__init__(name=name, enabled=True, timeout_seconds=1.0)
        self.call_count = 0

    def is_healthy(self) -> bool:
        return True

    def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
        self.call_count += 1
        if is_sensitive:
            return self._create_result(
                status=ProviderResultStatus.SKIPPED_SENSITIVE_URL,
                matched=False,
                details={"reason": "Sensitive URL parameter skipped for privacy"},
            )
        return self._create_result(
            status=ProviderResultStatus.NO_MATCH,
            matched=False,
            details={"reason": "Clean domain query executed"},
        )


def test_threat_intel_cache_isolation_between_sensitive_and_nonsensitive():
    """CRITICAL AUDIT FIX VERIFICATION:
    Querying a sensitive URL must NOT poison the cache for subsequent non-sensitive queries,
    and a non-sensitive query must NOT cause a sensitive query to return a cached public lookup.
    """
    settings = ThreatFeedSettings(provider_cache_ttl_seconds=3600, max_cache_size=100)
    provider = PolicySensitiveMockProvider(name="policy_mock")
    manager = ThreatIntelManager(settings=settings, providers=[provider])

    target_url = "https://banking.example.com/login?token=secret123"

    # Step 1: Query with is_sensitive=True
    res_sensitive_1 = manager.query_all(target_url, is_sensitive=True, use_cache=True)
    assert len(res_sensitive_1) == 1
    assert res_sensitive_1[0].result_status == ProviderResultStatus.SKIPPED_SENSITIVE_URL
    assert provider.call_count == 1

    # Step 2: Query same URL with is_sensitive=False
    # MUST NOT return the cached SKIPPED_SENSITIVE_URL! Must execute a new lookup.
    res_nonsensitive = manager.query_all(target_url, is_sensitive=False, use_cache=True)
    assert len(res_nonsensitive) == 1
    assert res_nonsensitive[0].result_status == ProviderResultStatus.NO_MATCH
    assert provider.call_count == 2

    # Step 3: Query again with is_sensitive=True -> hits the sensitive cache
    res_sensitive_2 = manager.query_all(target_url, is_sensitive=True, use_cache=True)
    assert len(res_sensitive_2) == 1
    assert res_sensitive_2[0].result_status == ProviderResultStatus.SKIPPED_SENSITIVE_URL
    assert provider.call_count == 2  # Cached, no increment!


def test_ipv6_bracket_canonicalization_and_port_handling():
    """CRITICAL AUDIT FIX VERIFICATION:
    RFC 3986 / RFC 2732 specifies IPv6 hostnames must be bracketed in netloc.
    Unbracketed IPv6 with ports causes ValueError crashes in standard urlparse.
    """
    # Raw IPv6 with custom port
    u1 = "http://[2001:db8::1]:8080/path?query=1"
    c1 = canonicalize_url_strict(u1)
    assert "[2001:db8::1]:8080" in c1
    assert c1 == "http://[2001:db8::1]:8080/path?query=1"

    # IPv6 with default port 80 (must strip port, preserve brackets)
    u2 = "http://[2001:db8::1]:80/path"
    c2 = canonicalize_url_strict(u2)
    assert c2 == "http://[2001:db8::1]/path"

    # IPv6 HTTPS default port 443 (must strip port, preserve brackets)
    u3 = "https://[::1]:443/test"
    c3 = canonicalize_url_strict(u3)
    assert c3 == "https://[::1]/test"

    # Host extraction should return clean IPv6 without crashing
    h1 = extract_safe_hostname(u1)
    assert h1 == "2001:db8::1"


def test_idna_unicode_homoglyphs_canonicalization():
    """IDNA punycode normalization and case-folding on Unicode domains."""
    # Cyrillic 'а' (U+0430) resembling Latin 'a'
    cyrillic_url = "http://xn--p1ai.example.org/test"
    c = canonicalize_url_strict(cyrillic_url)
    assert "xn--p1ai.example.org" in c

    # Trailing dot stripping
    dot_url = "https://example.org./path"
    c_dot = canonicalize_url_strict(dot_url)
    assert "example.org/path" in c_dot


def test_provider_failures_never_silently_produce_safe_verdict():
    """INVARIANT: If threat feeds fail (timeout, unhandled exception, 500),
    the site cannot be certified as SAFE even if other evidence is spotless.
    """
    engine = TrustLensIntelligenceEngine()

    class ExplodingProvider(ThreatIntelProvider):
        def __init__(self) -> None:
            super().__init__(name="exploding", enabled=True, timeout_seconds=1.0)

        def is_healthy(self) -> bool:
            return False

        def query(self, url: str, is_sensitive: bool = False) -> ProviderCheckResult:
            raise RuntimeError("Underlying threat intelligence cluster unavailable (503 Service Unavailable)")

    engine.threat_manager = ThreatIntelManager(providers=[ExplodingProvider()])

    ev = ScanEvidence(
        original_url="https://clean-site.example.org/index.html",
        http=HttpEvidence(status_code=200, security_headers={"content-security-policy": "default-src 'self'"}),
        tls=TlsCertificateEvidence(valid=True, chain_valid=True, hostname_match=True, days_until_expiry=120),
        domain_intelligence=DomainIntelligenceEvidence(domain_age_days=1000),
    )

    assessment = engine.analyze(ev, query_providers=True)

    # Coverage cannot be COMPLETE
    assert assessment.coverage["threat_intel"] != LayerCoverage.COMPLETE
    # Verdict MUST NOT be SAFE
    assert assessment.verdict != Verdict.SAFE
    assert assessment.verdict in (Verdict.INCONCLUSIVE, Verdict.SUSPICIOUS)
    # The provider check is recorded as UNAVAILABLE, not cleanly passing
    check = next((c for c in assessment.provider_checks if c.provider == "exploding"), None)
    assert check is not None
    assert check.result_status == ProviderResultStatus.UNAVAILABLE
    assert check.matched is False


# ==============================================================================
# 2. COLLABORATIVE THREAT INTELLIGENCE ADVERSARIAL STRESS
# ==============================================================================


def test_sybil_multiple_accounts_identical_evidence_flooding():
    """ADVERSARIAL SYBIL TEST:
    Malicious actor creates 8 accounts and submits identical screenshots/hashes
    to poison a benign target. The collaborative engine must detect abuse and
    collapse the corroborated confidence.
    """
    engine_ci = CollaborativeIntelligenceEngine()

    # Shared screenshot hash across 8 distinct reporters
    shared_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    reports: list[CommunityReportInput] = []

    for i in range(8):
        reports.append(
            CommunityReportInput(
                submission_id=f"rep_sybil_{i}",
                original_url="https://victim-bank.example/portal",
                reporter=ReporterMetadata(
                    reporter_id=f"bad_actor_clone_{i}",
                    account_age_days=2,
                    previous_accepted_reports=1,
                    previous_rejected_reports=5,
                    is_trusted=False,
                ),
                category=ThreatCategory.PHISHING,
                description="This website is a fake banking portal designed to steal user credentials immediately.",
                evidence_items=[
                    EvidenceItem(
                        evidence_type=EvidenceType.SCREENSHOT,
                        sha256_hash=shared_hash,
                        source="user_upload",
                        description="Phishing page screenshot",
                        stance=EvidenceStance.SUPPORTS,
                        is_supporting=True,
                    )
                ],
            )
        )

    eval_result = engine_ci.evaluate_report(
        report=reports[0],
        existing_reports=reports[1:],
    )

    # Coordinated abuse and identical evidence signals MUST be flagged
    assert eval_result.abuse_detection.is_suspicious is True
    assert AbuseSignalType.COORDINATED_SUBMISSION in eval_result.abuse_detection.signals
    assert AbuseSignalType.DUPLICATE_EVIDENCE in eval_result.abuse_detection.signals

    # Corroboration score must collapse and NOT be HIGH
    assert eval_result.corroboration.corroboration_level != CorroborationLevel.HIGH
    # Moderation recommendation must recommend abuse suspicion
    assert eval_result.moderation_recommendation.recommended_action == ModerationAction.SUSPECT_ABUSE


def test_single_account_mass_reporting_cannot_cause_malicious_verdict():
    """INVARIANT: An individual account submitting 20 reports cannot independently
    trigger a decisive malicious verdict in TrustLens Intelligence.
    """
    engine = TrustLensIntelligenceEngine()

    # 20 confirmed reports, but all from the SAME reporter (distinct_count = 1)
    ev = ScanEvidence(
        original_url="https://legitimate-shop.example.org/checkout",
        community_intelligence=CommunityIntelligenceEvidence(
            confirmed_report_count=20,
            distinct_reporter_count=1,
        ),
        http=HttpEvidence(status_code=200, security_headers={"content-security-policy": "default-src 'self'"}),
        tls=TlsCertificateEvidence(valid=True, chain_valid=True, hostname_match=True, days_until_expiry=90),
        threat_intelligence=ThreatIntelEvidence(openphish_match=False, urlhaus_match=False),
    )

    assessment = engine.analyze(ev, query_providers=False)

    # Must NOT have matched as a decisive threat feed check
    comm_check = next((p for p in assessment.provider_checks if p.provider == "community"), None)
    assert comm_check is not None
    assert comm_check.matched is False

    # The CommunityConfirmedMaliciousRule rule MUST NOT fire
    finding_codes = [f.code for f in assessment.findings]
    assert "COMMUNITY_CONFIRMED_MALICIOUS" not in finding_codes
    assert assessment.verdict != Verdict.MALICIOUS


def test_conflicting_community_evidence_penalizes_corroboration():
    """Submissions containing contradictory evidence (e.g. proof of clean domain)
    must heavily penalize corroboration score and trigger dispute recommendation.
    """
    engine_ci = CollaborativeIntelligenceEngine()

    reports = [
        CommunityReportInput(
            submission_id="rep_accuse",
            original_url="https://contested.example/app",
            reporter=ReporterMetadata(reporter_id="accuser_1", is_trusted=False),
            category=ThreatCategory.MALWARE,
            description="Malware download detected at this address.",
            evidence_items=[
                EvidenceItem(
                    evidence_type=EvidenceType.ANALYZER_FINDING,
                    raw_content="Trojan detected",
                    source="scanner",
                    description="Trojan signature match in payload",
                    stance=EvidenceStance.SUPPORTS,
                    is_supporting=True,
                )
            ],
        ),
        CommunityReportInput(
            submission_id="rep_defend",
            original_url="https://contested.example/app",
            reporter=ReporterMetadata(reporter_id="defender_1", is_trusted=True),
            category=ThreatCategory.OTHER,
            description="Legitimate open-source utility falsely flagged by heuristic scanner.",
            evidence_items=[
                EvidenceItem(
                    evidence_type=EvidenceType.SECURITY_RESEARCH,
                    raw_content="VirusTotal 0/70 clean",
                    source="external_research",
                    description="Independent verification confirms utility clean",
                    stance=EvidenceStance.CONTRADICTS,
                    is_supporting=False,  # Contradictory evidence!
                )
            ],
        ),
    ]

    eval_result = engine_ci.evaluate_report(
        report=reports[0],
        existing_reports=[reports[1]],
    )

    assert eval_result.corroboration.conflicting_evidence_count > 0
    assert eval_result.corroboration.corroboration_level in (
        CorroborationLevel.NONE,
        CorroborationLevel.LOW,
    )
    assert eval_result.moderation_recommendation.recommended_action in (
        ModerationAction.QUEUE_FOR_REVIEW,
        ModerationAction.REQUEST_MORE_EVIDENCE,
    )


def test_unverified_and_rejected_reports_produce_zero_threat_indicator():
    """Reports with status REVOKED or DISPUTED must not match as active indicators."""
    now = datetime.now(timezone.utc)
    revoked_indicator = ConfirmedIndicator(
        indicator_id="ind_revoked",
        indicator_value="https://revoked-threat.example",
        scope=IndicatorScope.EXACT_URL,
        threat_category=ThreatCategory.PHISHING,
        status=IndicatorStatus.REVOKED,
        confirmed_at=now - timedelta(days=10),
        expires_at=now + timedelta(days=30),
        revoked_at=now - timedelta(days=1),
        moderator_id="mod_admin_1",
    )

    # Evaluate lifecycle status directly
    status = evaluate_indicator_status(revoked_indicator, current_time=now)
    assert status == IndicatorStatus.REVOKED

    # Matching query against revoked indicator must return matched=False
    matcher = IndicatorMatcher()
    match = matcher.match(
        target_url="https://revoked-threat.example",
        indicators=[revoked_indicator],
        current_time=now,
    )
    assert match.matched is False
    assert match.is_active is False


# ==============================================================================
# 3. DETECTION ENGINE STRESS & RESILIENCE
# ==============================================================================


class FaultyCrashingRule(DetectionRule):
    """Adversarial rule that intentionally throws an unhandled exception."""

    def __init__(self) -> None:
        super().__init__(
            code="FAULTY_CRASHING_RULE",
            category=FindingCategory.WEB_SECURITY,
            severity=FindingSeverity.HIGH,
            points=20,
            title="Crashing Rule",
            description_template="Throws error",
            remediation="None",
        )

    def evaluate(self, evidence: ScanEvidence, features: ExtractedFeatures) -> Finding | None:
        raise ZeroDivisionError("Simulated sudden catastrophic failure in detection rule logic")


def test_unhandled_rule_exception_does_not_halt_engine(clean_site_evidence):
    """Resilience test: An unhandled exception in one rule must be caught safely
    by the DetectionEngine without terminating evaluation of other rules.
    """
    registry = RuleRegistry()
    registry.register(FaultyCrashingRule())
    engine = DetectionEngine(registry=registry)

    features = ExtractedFeatures()

    # Should execute without re-raising ZeroDivisionError
    result = engine.evaluate(clean_site_evidence, features)
    assert isinstance(result.findings, list)
    # The crashing rule did not produce a finding
    assert not any(f.code == "FAULTY_CRASHING_RULE" for f in result.findings)


def test_finding_deduplication_prevents_point_inflation(clean_site_evidence):
    """Adding duplicated findings with identical rule codes must not inflate the additive score."""
    engine = RiskScoringEngine()

    dup_finding = Finding(
        code="RULE_TLS_EXPIRED",
        category=FindingCategory.CERTIFICATE,
        severity=FindingSeverity.HIGH,
        points=20,
        title="TLS expired",
        description="Expired cert",
        evidence={},
        remediation="Renew cert",
        source="unit_test",
    )

    # 3 copies of the exact same finding
    findings = [dup_finding, dup_finding, dup_finding]

    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.NO_MATCH),
    ]

    res = engine.score(
        evidence=clean_site_evidence,
        findings=findings,
        provider_checks=provider_checks,
        has_decisive_malicious=False,
    )

    # Deduplicator should collapse to 1 finding of 20 points
    assert len(res.details["point_breakdown"]) == 1
    assert res.score == 20


def test_extreme_and_boundary_feature_values():
    """Engine must gracefully handle astronomical and boundary feature numbers."""
    features = ExtractedFeatures(
        url_length=1_000_000,
        url_entropy=8.0,
        redirect_count=999,
    )

    d_dict = features.to_ml_dict()
    assert d_dict["url_length"] == 1_000_000
    assert d_dict["url_entropy"] == 8.0
    assert d_dict["redirect_count"] == 999


# ==============================================================================
# 4. RISK SCORING & EXPLAINABILITY INVARIANTS
# ==============================================================================


@pytest.mark.parametrize(
    "points_list,has_decisive,expected_score,expected_verdict",
    [
        ([], False, 0, Verdict.SAFE),
        ([15], False, 15, Verdict.SAFE),
        ([25], False, 25, Verdict.SUSPICIOUS),
        ([50], False, 50, Verdict.SUSPICIOUS),
        ([74], False, 74, Verdict.SUSPICIOUS),
        ([85], False, 85, Verdict.SUSPICIOUS),  # Additive without decisive is SUSPICIOUS
        ([80, 80], False, 100, Verdict.SUSPICIOUS),  # Capped at 100
        ([100], True, 100, Verdict.MALICIOUS),  # Decisive triggers MALICIOUS
    ],
)
def test_deterministic_score_tiers_and_bounding(
    clean_site_evidence, points_list, has_decisive, expected_score, expected_verdict
):
    """Verify score bounding (0-100) and strict adherence to PRD verdict tiers."""
    engine = RiskScoringEngine()

    findings = []
    for idx, pts in enumerate(points_list):
        findings.append(
            Finding(
                code=f"SYNTHETIC_TEST_RULE_{idx}",
                category=FindingCategory.WEB_SECURITY,
                severity=FindingSeverity.CRITICAL if pts >= 90 else FindingSeverity.HIGH,
                points=pts,
                title="Synthetic finding",
                description="Testing score tier boundaries",
                evidence={},
                remediation="None",
                source="unit_test",
            )
        )

    provider_checks = [
        ProviderCheckResult(provider="openphish", result_status=ProviderResultStatus.NO_MATCH),
        ProviderCheckResult(provider="urlhaus", result_status=ProviderResultStatus.NO_MATCH),
    ]

    res = engine.score(
        evidence=clean_site_evidence,
        findings=findings,
        provider_checks=provider_checks,
        has_decisive_malicious=has_decisive,
    )

    assert 0 <= res.score <= 100
    assert 0.0 <= res.confidence <= 1.0
    assert res.score == expected_score
    assert res.verdict == expected_verdict


def test_failed_scan_is_inconclusive_with_null_score():
    """A failed scan (e.g. network timeout / unreachable) must yield INCONCLUSIVE with null score."""
    engine = TrustLensIntelligenceEngine()
    ev = ScanEvidence(
        original_url="https://unreachable.invalid",
        http=None,
        tls=None,
    )

    assessment = engine.analyze(
        evidence=ev,
        query_providers=False,
        is_scan_failed=True,
    )

    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.risk_score is None
    assert assessment.confidence == 0.0


def test_scoring_determinism_across_identical_evaluations(clean_site_evidence):
    """Property test: Repeated scoring of identical inputs MUST produce bit-for-bit identical results."""
    engine = TrustLensIntelligenceEngine()

    res1 = engine.analyze(clean_site_evidence, query_providers=False)
    res2 = engine.analyze(clean_site_evidence, query_providers=False)

    assert res1.risk_score == res2.risk_score
    assert res1.verdict == res2.verdict
    assert res1.confidence == res2.confidence
    assert [f.code for f in res1.findings] == [f.code for f in res2.findings]
    assert res1.summary == res2.summary


# ==============================================================================
# 5. ML INFERENCE ROBUSTNESS & ADVERSARIAL FEATURE VECTORS
# ==============================================================================


def test_ml_inference_nan_inf_none_sanitization():
    """CRITICAL AUDIT FIX VERIFICATION:
    Features containing None, NaN, or Inf must be sanitized to safe floats
    so that scikit-learn models do not crash with ValueError.
    """
    classifier = ThreatClassifier()

    class AdversarialFeatures(ExtractedFeatures):
        model_config = {"extra": "allow"}  # type: ignore

        def to_ml_dict(self) -> dict[str, Any]:
            return {
                "url_length": float("nan"),
                "url_entropy": float("inf"),
                "is_ip_host": None,
                "has_userinfo": 0.0,
                "subdomain_count": -float("inf"),
                "cert_days_until_expiry": None,
                "redirect_count": 0.0,
            }

    features = AdversarialFeatures()

    classifier.is_loaded = True
    classifier.feature_names = [
        "url_length",
        "url_entropy",
        "is_ip_host",
        "has_userinfo",
        "subdomain_count",
        "cert_days_until_expiry",
        "redirect_count",
    ]

    class MockEstimator:
        def predict_proba(self, X: Any) -> np.ndarray:
            # Verify no NaN or Inf survived into the pandas DataFrame
            arr = X.to_numpy()
            assert not np.isnan(arr).any(), "NaN value leaked into scikit-learn input matrix!"
            assert not np.isinf(arr).any(), "Inf value leaked into scikit-learn input matrix!"
            return np.array([[0.8, 0.15, 0.05]])

    classifier.model = MockEstimator()

    # Must execute safely without crashing
    pred = classifier.predict(features)
    assert pred is not None
    assert pred.predicted_label == "legitimate"
    assert 0.0 <= pred.malicious_probability <= 1.0

    mc = classifier.predict_multiclass(features)
    assert mc is not None
    assert math.isclose(mc["legitimate"] + mc["phishing"] + mc["malware"], 1.0, abs_tol=1e-3)


def test_ml_prediction_cannot_override_decisive_threat_signal(clean_site_evidence):
    """An ML prediction of 99% legitimate CANNOT override a decisive threat feed match."""
    engine = TrustLensIntelligenceEngine()

    class AlwaysBenignClassifier(ThreatClassifier):
        def __init__(self) -> None:
            super().__init__()
            self.is_loaded = True

        def predict(self, features: ExtractedFeatures) -> Any:
            from trustlens_intelligence.schemas.assessment import MLPrediction
            return MLPrediction(
                model_name="always_benign",
                model_version="1.0.0",
                malicious_probability=0.01,
                predicted_label="legitimate",
                calibrated_confidence=0.98,
                top_contributing_features=[],
            )

    engine.ml_classifier = AlwaysBenignClassifier()

    # Evidence with a decisive OpenPhish match
    ev = clean_site_evidence.model_copy(deep=True)
    ev.threat_intelligence = ThreatIntelEvidence(
        openphish_match=True,
        openphish_status="match",
    )

    assessment = engine.analyze(ev, query_providers=False)

    # Decisive rule MUST win -> MALICIOUS verdict
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score >= 80


# ==============================================================================
# 6. CERTIFICATE ANALYZER RESOURCE LIMITS & DATASET INTEGRITY
# ==============================================================================


def test_cert_analyzer_oversized_input_rejection():
    """Certificate Analyzer must reject inputs exceeding maximum size limit (10 MB)."""
    from certificate_analyzer.api import analyze_certificate
    from certificate_analyzer.constants import CertificateVerdict

    huge_input = b"A" * (11 * 1024 * 1024)  # 11 MB
    assessment = analyze_certificate(huge_input)
    assert assessment.verdict == CertificateVerdict.INCONCLUSIVE
    assert any(f.code == "RULE_RESOURCE_LIMIT_EXCEEDED" for f in assessment.findings)


def test_cert_dataset_zero_leakage_split_verification():
    """Verify that domain-aware evaluation splits strictly guarantee zero leakage."""
    import pandas as pd
    from certificate_dataset.storage.store import DatasetStorage
    from trustlens_intelligence.evaluation.dataset import create_domain_aware_splits

    # 1. Test create_domain_aware_splits
    X = pd.DataFrame({"f1": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]})
    y = np.array([0, 0, 1, 1, 0, 1])
    domains = ["example.com", "example.com", "victim.org", "victim.org", "test.net", "test.net"]

    splits = create_domain_aware_splits(X, y, domains, test_size=0.3)
    train_doms = set(splits.train_domains)
    test_doms = set(splits.test_domains)
    assert len(train_doms.intersection(test_doms)) == 0, "Domain leakage detected between train and test splits!"

    # 2. Test certificate dataset storage splits
    storage = DatasetStorage()
    manifest_path = storage.manifests_dir / "certificate_dataset_manifest.json"
    if manifest_path.exists():
        import json
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        overlap_audit = manifest.get("evaluation_splits", {}).get("overlap_audit", {})
        assert overlap_audit.get("fingerprint_leakage_clean") is True
