"""Model trainer, validator, artifact saver, and manifest generator."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, Optional

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
_DATASET_SRC = _INTELLIGENCE_DIR / "certificate_dataset" / "src"
for p in [_DEPS_DIR, _DATASET_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import joblib

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


class CertificateMLTrainer:
    """Orchestrates model fitting, selection on validation split, evaluation on locked test, and artifact persistence."""

    def __init__(self, artifacts_dir: Optional[Path] = None):
        self.artifacts_dir = artifacts_dir or Path(__file__).parent / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.dataset_loader = CertificateMLDataset()

    def train_and_evaluate(self, split_type: str = "spki_disjoint") -> Dict[str, Any]:
        """Executes full training pipeline across all candidate architectures."""
        print(f"Loading split '{split_type}'...")
        splits = self.dataset_loader.load_split_records(split_type=split_type)
        labels_map = self.dataset_loader.get_labels_map()

        df_train = self.dataset_loader.extract_tabular_features(splits["train"], labels_map)
        df_val = self.dataset_loader.extract_tabular_features(splits["val"], labels_map)
        df_test = self.dataset_loader.extract_tabular_features(splits["test"], labels_map)

        print(f"Training samples:   {len(df_train)} (Positive: {df_train['target'].sum()}, Negative: {len(df_train) - df_train['target'].sum()})")
        print(f"Validation samples: {len(df_val)} (Positive: {df_val['target'].sum()}, Negative: {len(df_val) - df_val['target'].sum()})")
        print(f"Test samples:       {len(df_test)} (Positive: {df_test['target'].sum()}, Negative: {len(df_test) - df_test['target'].sum()})")

        feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
        X_train, y_train = df_train[feature_cols], df_train["target"].to_numpy()
        X_val, y_val = df_val[feature_cols], df_val["target"].to_numpy()
        X_test, y_test = df_test[feature_cols], df_test["target"].to_numpy()

        candidates = CertificateModelFactory.get_candidate_models()
        best_name = ""
        best_val_macro_f1 = -1.0
        best_pipeline = None
        all_candidate_metrics = {}

        for name, pipeline in candidates.items():
            print(f"Fitting candidate model: {name}...")
            pipeline.fit(X_train, y_train)

            # Val metrics
            val_preds = pipeline.predict(X_val)
            val_probs = pipeline.predict_proba(X_val)[:, 1] if hasattr(pipeline, "predict_proba") else None
            val_metrics = CertificateMLEvaluator.evaluate(y_val, val_preds, val_probs)
            all_candidate_metrics[name] = val_metrics
            print(f"  {name} -> Val Macro-F1: {val_metrics['macro_f1']:.4f}, Accuracy: {val_metrics['accuracy']:.4f}, ROC-AUC: {val_metrics.get('roc_auc')}")

            if val_metrics["macro_f1"] > best_val_macro_f1:
                best_val_macro_f1 = val_metrics["macro_f1"]
                best_name = name
                best_pipeline = pipeline

        print(f"Selected champion: {best_name} (Val Macro-F1: {best_val_macro_f1:.4f})")

        # Evaluate champion on Train, Val, and Locked Test
        train_preds = best_pipeline.predict(X_train)
        train_probs = best_pipeline.predict_proba(X_train)[:, 1] if hasattr(best_pipeline, "predict_proba") else None
        train_metrics = CertificateMLEvaluator.evaluate(y_train, train_preds, train_probs)

        test_preds = best_pipeline.predict(X_test)
        test_probs = best_pipeline.predict_proba(X_test)[:, 1] if hasattr(best_pipeline, "predict_proba") else None
        test_metrics = CertificateMLEvaluator.evaluate(y_test, test_preds, test_probs)

        gap = CertificateMLEvaluator.compute_generalization_gap(
            train_metrics=train_metrics,
            val_metrics=all_candidate_metrics[best_name],
            test_metrics=test_metrics,
        )

        # Train auxiliary Isolation Forest for Profile Anomaly Detection
        print("Training auxiliary Isolation Forest anomaly detector on compliant training records...")
        X_train_compliant = X_train[y_train == 1]
        anomaly_detector = CertificateModelFactory.get_anomaly_detector()
        anomaly_detector.fit(X_train_compliant)

        # Save model artifacts
        champion_path = self.artifacts_dir / "champion_model.joblib"
        anomaly_path = self.artifacts_dir / "anomaly_detector.joblib"
        joblib.dump(best_pipeline, champion_path)
        joblib.dump(anomaly_detector, anomaly_path)

        now_utc = datetime.now(timezone.utc).isoformat()
        manifest: Dict[str, Any] = {
            "model_name": "TrustLens-Certificate-Policy-Classifier",
            "model_version": "1.0.0",
            "model_type": "Advisory Surrogate / Policy Profile Classifier",
            "champion_algorithm": best_name,
            "trained_timestamp": now_utc,
            "split_strategy": split_type,
            "zero_leakage_guarantee": "Zero SPKI public-key overlap and zero fingerprint overlap between train, val, and test splits.",
            "feature_schema": {
                "numeric_features": NUMERIC_FEATURES,
                "categorical_features": CATEGORICAL_FEATURES,
            },
            "candidate_comparisons": all_candidate_metrics,
            "champion_metrics": {
                "train": train_metrics,
                "validation": all_candidate_metrics[best_name],
                "locked_test": test_metrics,
                "generalization_gap": gap,
            },
            "artifacts": {
                "champion_model_file": str(champion_path.name),
                "anomaly_detector_file": str(anomaly_path.name),
            },
            "operational_role": "ADVISORY ONLY. Must NOT override deterministic PKI validation results (expired, untrusted root, hostname mismatch, revoked).",
            "known_limitations": [
                "Trained exclusively on raw structural parameters without target leakage.",
                "Serves as a rapid auxiliary policy filter and anomalous profile detector.",
                "Ground truth labels reflect CA/B Forum Baseline Requirements v2.0.8 policy rules.",
            ],
        }

        manifest_path = self.artifacts_dir / "model_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        print(f"Artifacts successfully persisted to {self.artifacts_dir}!")
        return manifest


if __name__ == "__main__":
    trainer = CertificateMLTrainer()
    res = trainer.train_and_evaluate(split_type="spki_disjoint")
    print(json.dumps(res["champion_metrics"]["locked_test"], indent=2))

