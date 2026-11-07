"""Tests for TrustLens Machine Learning Pipeline, Training, and Inference."""

import tempfile
from pathlib import Path
import pytest

from trustlens_intelligence.evaluation.dataset import (
    create_domain_aware_splits,
    generate_benchmark_dataset,
)
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.evaluation.metrics import compute_classification_metrics
from trustlens_intelligence.evaluation.models import (
    build_logistic_regression_pipeline,
    build_random_forest_pipeline,
)
from trustlens_intelligence.evaluation.trainer import ModelTrainer
from trustlens_intelligence.features.extractor import FeatureExtractor
from trustlens_intelligence.schemas.evidence import ScanEvidence


def test_domain_aware_split_no_leakage():
    """Domains present in train set must NEVER appear in test set."""
    X, y, domains = generate_benchmark_dataset(sample_multiplier=2)
    splits = create_domain_aware_splits(X, y, domains, test_size=0.3)

    train_domains = set(splits.train_domains)
    test_domains = set(splits.test_domains)

    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, f"Data leakage detected! Shared domains: {overlap}"
    assert len(train_domains) > 0
    assert len(test_domains) > 0


def test_baseline_models_and_metrics():
    """Train baseline models and evaluate classification metrics."""
    X, y, domains = generate_benchmark_dataset(sample_multiplier=3)
    splits = create_domain_aware_splits(X, y, domains, test_size=0.3)

    lr_pipeline = build_logistic_regression_pipeline()
    lr_pipeline.fit(splits.X_train, splits.y_train)
    y_pred = lr_pipeline.predict(splits.X_test)
    y_proba = lr_pipeline.predict_proba(splits.X_test)[:, 1]

    metrics = compute_classification_metrics(splits.y_test, y_pred, y_proba, model_name="logistic_regression")
    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.f1 <= 1.0
    assert 0.0 <= metrics.pr_auc <= 1.0
    assert len(metrics.confusion_matrix) == 2


def test_model_trainer_and_artifact_saving():
    """Train comparison and save model artifact."""
    trainer = ModelTrainer()
    results = trainer.train_and_compare()
    assert len(results) >= 2

    with tempfile.TemporaryDirectory() as tmp_dir:
        art_path = Path(tmp_dir) / "test_model.joblib"
        artifact = trainer.save_best_model(results, art_path)
        assert art_path.exists()
        assert artifact["model_name"] in results

        # Test ThreatClassifier loading artifact
        classifier = ThreatClassifier(art_path)
        assert classifier.is_loaded is True

        # Test inference
        ev = ScanEvidence(original_url="http://192.168.1.1/admin/login?pwd=123")
        features = FeatureExtractor().extract(ev)
        pred = classifier.predict(features)
        assert pred is not None
        assert 0.0 <= pred.malicious_probability <= 1.0
        assert pred.predicted_label in ("legitimate", "suspicious", "malicious")


def test_threat_classifier_graceful_failure():
    """Inference must gracefully return None if model is uninitialized or corrupt."""
    classifier = ThreatClassifier()
    assert classifier.is_loaded is False

    # Loading non-existent path or directory returns False without crashing
    assert classifier.load_artifact(Path(__file__).parent) is False
    assert classifier.load_artifact("/path/that/does/not/exist.joblib") is False

    ev = ScanEvidence(original_url="https://example.com")
    features = FeatureExtractor().extract(ev)
    pred = classifier.predict(features)
    assert pred is None  # Does not crash or raise exception


def test_threat_classifier_bundled_default_model():
    """Verify that bundled default baseline model loads and produces calibrated prediction."""
    classifier = ThreatClassifier.load_default()
    assert classifier.is_loaded is True
    assert classifier.model_name in ("logistic_regression", "random_forest", "gradient_boosting")
    assert len(classifier.feature_names) > 30

    ev = ScanEvidence(original_url="https://secure.banking-login-verify.com/account")
    features = FeatureExtractor().extract(ev)
    pred = classifier.predict(features)
    assert pred is not None
    assert 0.0 <= pred.malicious_probability <= 1.0
    assert pred.predicted_label in ("legitimate", "suspicious", "malicious")
    assert 0.0 <= pred.calibrated_confidence <= 1.0

