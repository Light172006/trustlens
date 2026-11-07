"""TrustLens Intelligence — Candidate Multi-Class Model Integration and Generalization Tests.

Verifies:
1. Candidate artifact loading and metadata schema compliance.
2. Three-class probability distribution invariants (sums to 1.0, non-negative).
3. Backwards-compatible binary projection in MLPrediction.
4. Deep benign URL regression tests (zero false positives).
5. Phishing detection on high-entropy credential harvesting URLs.
6. Deterministic scoring independence and failure resilience.
7. Missing evidence preservation (no false SAFE verdicts).
8. Authoritative threat feed decisive scoring invariance.
"""

from pathlib import Path
import pytest
from trustlens_intelligence.api import TrustLensIntelligenceEngine
from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION, MODEL_SCHEMA_VERSION
from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.schemas.assessment import Verdict
from trustlens_intelligence.schemas.evidence import (
    ScanEvidence,
    ThreatIntelEvidence,
)


@pytest.fixture
def candidate_classifier() -> ThreatClassifier:
    """Fixture providing loaded candidate multi-class classifier."""
    cand = ThreatClassifier.load_candidate()
    assert cand.is_loaded, "Candidate classifier artifact must be present and loaded"
    return cand


def test_candidate_artifact_loading(candidate_classifier: ThreatClassifier):
    """Verify candidate artifact loads with correct metadata and feature names."""
    assert candidate_classifier.is_loaded
    assert candidate_classifier.model_name == "soft_voting_ensemble_multiclass"
    assert candidate_classifier.model_version == "2.1.0"
    assert len(candidate_classifier.feature_names) == len(ML_INTRINSIC_FEATURE_NAMES)
    assert candidate_classifier.classes == ["legitimate", "phishing", "malware"]


def test_candidate_multiclass_probabilities_sum_to_one(candidate_classifier: ThreatClassifier):
    """Verify that multi-class inference produces valid probabilities that sum to 1.0."""
    ev = ScanEvidence(
        scan_id="test-multiclass-invariants",
        original_url="https://docs.python.org/3/library/urllib.parse.html",
        canonical_url="https://docs.python.org/3/library/urllib.parse.html",
    )
    engine = TrustLensIntelligenceEngine(classifier=candidate_classifier)
    assessment = engine.analyze(ev)
    assert assessment.features is not None

    probas = candidate_classifier.predict_multiclass(assessment.features)
    assert probas is not None
    assert "legitimate" in probas
    assert "phishing" in probas
    assert "malware" in probas
    assert "threat" in probas

    p_legit = probas["legitimate"]
    p_phish = probas["phishing"]
    p_mal = probas["malware"]
    p_threat = probas["threat"]

    assert 0.0 <= p_legit <= 1.0
    assert 0.0 <= p_phish <= 1.0
    assert 0.0 <= p_mal <= 1.0
    assert pytest.approx(p_legit + p_phish + p_mal, abs=1e-3) == 1.0
    assert pytest.approx(p_phish + p_mal, abs=1e-3) == p_threat


def test_candidate_benign_deep_url_regression(candidate_classifier: ThreatClassifier):
    """Regression test ensuring real-world deep benign URLs do not trigger false positives."""
    deep_benign_urls = [
        "https://en.wikipedia.org/wiki/Transport_Layer_Security",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "https://stackoverflow.com/questions/1234567/how-do-i-parse-a-url-in-python",
        "https://github.com/torvalds/linux/commits/master",
        "https://aws.amazon.com/security/introduction/?sec-nav=true",
        "https://cloud.google.com/bigquery/docs/quickstarts",
        "https://stripe.com/docs/api/charges/create",
    ]

    engine = TrustLensIntelligenceEngine(classifier=candidate_classifier)
    for url in deep_benign_urls:
        ev = ScanEvidence(
            scan_id=f"benign-reg-{url[:15]}",
            original_url=url,
            canonical_url=url,
        )
        assessment = engine.analyze(ev)
        assert assessment.ml_prediction is not None, f"ML prediction must be computed for {url}"
        assert assessment.ml_prediction.predicted_label == "legitimate", (
            f"Expected legitimate label for {url}, got {assessment.ml_prediction.predicted_label}"
        )
        assert assessment.ml_prediction.malicious_probability < 0.50, (
            f"Expected threat proba < 0.50 for {url}, got {assessment.ml_prediction.malicious_probability}"
        )


def test_candidate_phishing_detection(candidate_classifier: ThreatClassifier):
    """Verify that phishing-pattern URLs are classified as suspicious or malicious."""
    phishing_url = "https://secure-login-account-update.xyz/webscr/login.php"
    ev = ScanEvidence(
        scan_id="phish-test",
        original_url=phishing_url,
        canonical_url=phishing_url,
    )
    engine = TrustLensIntelligenceEngine(classifier=candidate_classifier)
    assessment = engine.analyze(ev)

    assert assessment.ml_prediction is not None
    assert assessment.ml_prediction.predicted_label in ("suspicious", "malicious")
    assert assessment.ml_prediction.malicious_probability >= 0.50

    mc = candidate_classifier.predict_multiclass(assessment.features)
    assert mc is not None
    assert mc["phishing"] > mc["malware"], "Deceptive login should have higher phishing than malware probability"


def test_deterministic_resilience_on_ml_failure():
    """Verify that ML failure or uninitialized classifier does not break deterministic analysis."""
    unloaded_classifier = ThreatClassifier()
    assert not unloaded_classifier.is_loaded

    engine = TrustLensIntelligenceEngine(classifier=unloaded_classifier)
    ev = ScanEvidence(
        scan_id="unloaded-test",
        original_url="https://example.com/test",
        canonical_url="https://example.com/test",
    )
    assessment = engine.analyze(ev)

    assert assessment.ml_prediction is None
    assert assessment.verdict in (Verdict.SAFE, Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.INCONCLUSIVE)
    assert assessment.summary != ""


def test_missing_evidence_prevents_false_safe_with_candidate(candidate_classifier: ThreatClassifier):
    """Verify that missing TLS/HTTP evidence preserves INCONCLUSIVE verdict even if ML predicts legitimate."""
    ev = ScanEvidence(
        scan_id="missing-evidence-test",
        original_url="https://example.com/",
        canonical_url="https://example.com/",
    )
    engine = TrustLensIntelligenceEngine(classifier=candidate_classifier)
    assessment = engine.analyze(ev)

    # ML predicts legitimate, but lack of observations MUST produce INCONCLUSIVE verdict
    assert assessment.ml_prediction is not None
    assert assessment.ml_prediction.predicted_label == "legitimate"
    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.risk_score == 0 or assessment.risk_score is None


def test_threat_match_overrides_ml_with_candidate(candidate_classifier: ThreatClassifier):
    """Verify that authoritative threat feed matches override ML predictions decisively."""
    ev = ScanEvidence(
        scan_id="threat-match-override",
        original_url="https://en.wikipedia.org/wiki/Transport_Layer_Security",
        canonical_url="https://en.wikipedia.org/wiki/Transport_Layer_Security",
        threat_intelligence=ThreatIntelEvidence(
            openphish_match=True,
            openphish_status="match",
        ),
    )
    engine = TrustLensIntelligenceEngine(classifier=candidate_classifier)
    assessment = engine.analyze(ev)

    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.risk_score == 100
    assert any(f.code == "OPENPHISH_URL_MATCH" for f in assessment.findings)
