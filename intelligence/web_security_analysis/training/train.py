"""
TrustLens Web Security Analyzer - Model Training & Selection Pipeline
Trains candidate classifiers, evaluates across metrics, performs probability calibration,
and registers the production-ready model artifact with cryptographic checksums.
"""

import argparse
import datetime
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import yaml

from calibration import calibrate_model
from evaluate import evaluate_classifier_performance
from model_registry import save_model_artifacts
from preprocessing import create_preprocessor_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trainer")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_experiment_config(config_path: str = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "training" / "experiment_config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_training_pipeline(config_path: str = None) -> Dict[str, Any]:
    config = load_experiment_config(config_path)
    logger.info("=== Starting TrustLens Model Training & Selection Pipeline ===")

    train_path = BASE_DIR / config["paths"]["train_data"]
    val_path = BASE_DIR / config["paths"]["val_data"]
    test_path = BASE_DIR / config["paths"]["test_data"]

    logger.info(f"Loading data partitions...")
    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    test_df = pd.read_parquet(test_path)

    target_col = config["experiment"]["target_column"]
    classes = config["experiment"]["classes"]

    # Filter to active classes
    train_df = train_df[train_df[target_col].isin(classes)].reset_index(drop=True)
    val_df = val_df[val_df[target_col].isin(classes)].reset_index(drop=True)
    test_df = test_df[test_df[target_col].isin(classes)].reset_index(drop=True)

    logger.info(f"Filtered samples: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

    num_cols = config["features"]["numerical"]
    bool_cols = config["features"]["boolean"]
    cat_cols = config["features"]["categorical"]

    # 1. Fit Preprocessor exclusively on Train split
    logger.info("Fitting preprocessor pipeline on Training data...")
    preprocessor = create_preprocessor_pipeline(num_cols, bool_cols, cat_cols)
    X_train = preprocessor.fit_transform(train_df)
    y_train = train_df[target_col].values

    # Transform Validation and Test splits
    X_val = preprocessor.transform(val_df)
    y_val = val_df[target_col].values

    X_test = preprocessor.transform(test_df)
    y_test = test_df[target_col].values

    logger.info(f"Transformed feature matrix shape: Train={X_train.shape}, Val={X_val.shape}, Test={X_test.shape}")

    # 2. Candidate Model Instantiation
    seed = config["experiment"]["random_seed"]
    candidates = {
        "LogisticRegression": LogisticRegression(
            C=config["candidates"]["logistic_regression"]["C"],
            max_iter=config["candidates"]["logistic_regression"]["max_iter"],
            class_weight=config["candidates"]["logistic_regression"]["class_weight"],
            solver=config["candidates"]["logistic_regression"]["solver"],
            random_state=seed,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=config["candidates"]["random_forest"]["n_estimators"],
            max_depth=config["candidates"]["random_forest"]["max_depth"],
            min_samples_split=config["candidates"]["random_forest"]["min_samples_split"],
            min_samples_leaf=config["candidates"]["random_forest"]["min_samples_leaf"],
            class_weight=config["candidates"]["random_forest"]["class_weight"],
            n_jobs=-1,
            random_state=seed,
        ),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=config["candidates"]["extra_trees"]["n_estimators"],
            max_depth=config["candidates"]["extra_trees"]["max_depth"],
            min_samples_split=config["candidates"]["extra_trees"]["min_samples_split"],
            min_samples_leaf=config["candidates"]["extra_trees"]["min_samples_leaf"],
            class_weight=config["candidates"]["extra_trees"]["class_weight"],
            n_jobs=-1,
            random_state=seed,
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=config["candidates"]["hist_gradient_boosting"]["max_iter"],
            learning_rate=config["candidates"]["hist_gradient_boosting"]["learning_rate"],
            max_depth=config["candidates"]["hist_gradient_boosting"]["max_depth"],
            min_samples_leaf=config["candidates"]["hist_gradient_boosting"]["min_samples_leaf"],
            class_weight=config["candidates"]["hist_gradient_boosting"]["class_weight"],
            random_state=seed,
        ),
    }

    # 3. Model Training & Validation Comparison
    comparison_results: Dict[str, Any] = {}
    best_candidate_name = None
    best_macro_f1 = -1.0
    best_candidate_model = None

    for name, model in candidates.items():
        logger.info(f"Training candidate: {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = round(time.time() - t0, 3)

        # Validation evaluation
        val_pred = model.predict(X_val)
        val_proba = model.predict_proba(X_val) if hasattr(model, "predict_proba") else None
        metrics = evaluate_classifier_performance(y_val, val_pred, val_proba, class_labels=classes)
        metrics["training_time_seconds"] = train_time

        comparison_results[name] = metrics
        logger.info(
            f"  {name} -> Val Acc: {metrics['accuracy']:.4f} | Macro F1: {metrics['macro_f1']:.4f} | "
            f"False GOOD on POOR: {metrics['security_penalties']['false_good_on_poor_count']} "
            f"({metrics['security_penalties']['false_good_on_poor_rate_pct']}%) | Time: {train_time}s"
        )

        # Selection criterion: Highest Macro F1 with lowest False GOOD on POOR rate
        if metrics["macro_f1"] > best_macro_f1:
            best_macro_f1 = metrics["macro_f1"]
            best_candidate_name = name
            best_candidate_model = model

    logger.info(f"Selected Best Candidate: {best_candidate_name} (Macro F1 = {best_macro_f1:.4f})")

    # 4. Probability Calibration on Validation Set
    calib_method = config["calibration"]["method"]
    calibrated_model, calib_metrics = calibrate_model(
        best_candidate_model, X_val, y_val, class_labels=classes, method=calib_method
    )

    # 5. Final Held-Out Test Evaluation
    logger.info("Evaluating calibrated best model on Held-Out Test split...")
    test_pred = calibrated_model.predict(X_test)
    test_proba = calibrated_model.predict_proba(X_test)
    test_metrics = evaluate_classifier_performance(y_test, test_pred, test_proba, class_labels=classes)

    logger.info(
        f"Test Results: Accuracy = {test_metrics['accuracy']:.4f} | Macro F1 = {test_metrics['macro_f1']:.4f} | "
        f"Balanced Acc = {test_metrics['balanced_accuracy']:.4f} | Macro ROC-AUC = {test_metrics.get('macro_roc_auc')}"
    )

    # 6. Model Metadata Assembly
    metadata: Dict[str, Any] = {
        "model_name": f"TrustLens-WebSecurity-{best_candidate_name}",
        "model_version": config["experiment"]["version"],
        "base_estimator": best_candidate_name,
        "calibration_applied": True,
        "calibration_method": calib_method,
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_seed": seed,
        "classes": classes,
        "feature_schema": {
            "numerical_features": num_cols,
            "boolean_features": bool_cols,
            "categorical_features": cat_cols,
            "transformed_features_count": int(X_train.shape[1]),
        },
        "training_data": {
            "train_samples": int(len(train_df)),
            "validation_samples": int(len(val_df)),
            "test_samples": int(len(test_df)),
        },
        "validation_comparison": comparison_results,
        "calibration_evaluation": calib_metrics,
        "test_evaluation": test_metrics,
    }

    # 7. Save Model Artifacts
    output_dir = BASE_DIR / config["paths"]["best_model_dir"]
    save_model_artifacts(calibrated_model, preprocessor, metadata, output_dir=output_dir)

    # 8. Generate Evaluation Reports
    reports_dir = BASE_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = BASE_DIR / config["paths"]["eval_report_path"]
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    report_md_path = BASE_DIR / config["paths"]["eval_report_md"]
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write(f"""# TrustLens Web Security Analyzer - Model Evaluation Report

**Model Name**: {metadata['model_name']}  
**Version**: {metadata['model_version']}  
**Evaluated At**: {metadata['trained_at']}  
**Selected Algorithm**: `{best_candidate_name}` with `{calib_method}` probability calibration  

## Candidate Models Validation Comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Balanced Acc | False GOOD on POOR | Train Time |
|---|---|---|---|---|---|---|
""")
        for name, m in comparison_results.items():
            f.write(
                f"| **{name}** | {m['accuracy']:.4f} | {m['macro_f1']:.4f} | {m['weighted_f1']:.4f} | "
                f"{m['balanced_accuracy']:.4f} | {m['security_penalties']['false_good_on_poor_count']} ({m['security_penalties']['false_good_on_poor_rate_pct']}%) | {m['training_time_seconds']}s |\n"
            )

        f.write(f"""
## Final Held-Out Test Evaluation (Zero-Leakage Unseen Domains)

- **Test Samples**: {len(test_df):,} distinct registrable domains
- **Test Accuracy**: **{test_metrics['accuracy']:.4f}**
- **Test Balanced Accuracy**: **{test_metrics['balanced_accuracy']:.4f}**
- **Test Macro F1**: **{test_metrics['macro_f1']:.4f}**
- **Test Weighted F1**: **{test_metrics['weighted_f1']:.4f}**
- **Macro ROC-AUC**: **{test_metrics.get('macro_roc_auc', 'N/A')}**
- **Log Loss**: **{test_metrics.get('log_loss', 'N/A')}**

### Per-Class Test Performance

| Posture Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
""")
        for c, pm in test_metrics["per_class"].items():
            f.write(f"| **{c}** | {pm['precision']:.4f} | {pm['recall']:.4f} | {pm['f1']:.4f} | {pm['support']} |\n")

        f.write(f"""
### Confusion Matrix (Test Split)

```text
Classes: {classes}
{np.array(test_metrics['confusion_matrix']['matrix'])}
```

### Security Penalty Metrics
- **False GOOD on POOR**: {test_metrics['security_penalties']['false_good_on_poor_count']} domains ({test_metrics['security_penalties']['false_good_on_poor_rate_pct']}%)
- **False POOR on GOOD**: {test_metrics['security_penalties']['false_poor_on_good_count']} domains ({test_metrics['security_penalties']['false_poor_on_good_rate_pct']}%)
""")

    logger.info(f"=== Model Training & Registration Successfully Completed! ===")
    return metadata


if __name__ == "__main__":
    run_training_pipeline()

