"""TrustLens Intelligence — Model Training and Benchmarking Pipeline."""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any
import joblib
import pandas as pd

from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION, MODEL_SCHEMA_VERSION
from trustlens_intelligence.evaluation.dataset import (
    DatasetSplits,
    create_domain_aware_splits,
    generate_benchmark_dataset,
)
from trustlens_intelligence.evaluation.metrics import EvaluationMetrics, compute_classification_metrics
from trustlens_intelligence.evaluation.models import get_available_model_factories

logger = logging.getLogger("trustlens.intelligence.evaluation.trainer")


class ModelTrainer:
    """Trains, compares, and packages threat detection classifiers."""

    def __init__(self, splits: DatasetSplits | None = None) -> None:
        if splits is not None:
            self.splits = splits
        else:
            X, y, domains = generate_benchmark_dataset()
            self.splits = create_domain_aware_splits(X, y, domains)

    def train_and_compare(self) -> dict[str, tuple[Any, EvaluationMetrics]]:
        """Train and evaluate all baseline models on the holdout split."""
        factories = get_available_model_factories()
        results: dict[str, tuple[Any, EvaluationMetrics]] = {}

        for name, factory in factories.items():
            logger.info("Training baseline model: %s", name)
            model = factory()
            model.fit(self.splits.X_train, self.splits.y_train)

            # Predict on test set
            y_pred = model.predict(self.splits.X_test)
            if hasattr(model, "predict_proba"):
                y_proba = model.predict_proba(self.splits.X_test)[:, 1]
            else:
                y_proba = y_pred.astype(float)

            metrics = compute_classification_metrics(
                y_true=self.splits.y_test,
                y_pred=y_pred,
                y_proba=y_proba,
                model_name=name,
            )
            results[name] = (model, metrics)
            logger.info(
                "Model %s - F1: %.4f, PR-AUC: %.4f, FPR: %.4f",
                name,
                metrics.f1,
                metrics.pr_auc,
                metrics.false_positive_rate,
            )

        return results

    def save_best_model(
        self,
        results: dict[str, tuple[Any, EvaluationMetrics]],
        output_path: str | Path,
    ) -> dict[str, Any]:
        """Save the highest performing model artifact with complete audit metadata."""
        # Select best model based on F1 and PR-AUC
        best_name = max(results.keys(), key=lambda k: results[k][1].f1 + results[k][1].pr_auc)
        best_model, best_metrics = results[best_name]

        artifact = {
            "model": best_model,
            "model_name": best_name,
            "model_version": "1.0.0",
            "schema_version": MODEL_SCHEMA_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": self.splits.feature_names,
            "evaluation_metrics": best_metrics.to_dict(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(artifact, path)
        logger.info("Saved best model artifact (%s) to %s", best_name, path)

        return artifact

