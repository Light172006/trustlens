"""TrustLens Intelligence Evaluation and ML Package."""

from trustlens_intelligence.evaluation.dataset import (
    DatasetSplits,
    create_domain_aware_splits,
    generate_benchmark_dataset,
    seed_record_to_evidence,
)
from trustlens_intelligence.evaluation.inference import ThreatClassifier
from trustlens_intelligence.evaluation.metrics import EvaluationMetrics, compute_classification_metrics
from trustlens_intelligence.evaluation.models import (
    build_gradient_boosting_pipeline,
    build_logistic_regression_pipeline,
    build_random_forest_pipeline,
    get_available_model_factories,
)
from trustlens_intelligence.evaluation.trainer import ModelTrainer

__all__ = [
    "DatasetSplits",
    "generate_benchmark_dataset",
    "create_domain_aware_splits",
    "seed_record_to_evidence",
    "EvaluationMetrics",
    "compute_classification_metrics",
    "build_logistic_regression_pipeline",
    "build_random_forest_pipeline",
    "build_gradient_boosting_pipeline",
    "get_available_model_factories",
    "ModelTrainer",
    "ThreatClassifier",
]

