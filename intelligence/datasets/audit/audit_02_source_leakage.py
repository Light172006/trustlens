"""Audit Module 2: Source Leakage and Missingness Classifier.

Evaluates whether the 34 intrinsic features or feature missingness/sentinels
leak the originating data source (Tranco, PhishTank, URLhaus, OpenPhish).
"""

import json
from pathlib import Path
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupKFold

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES


def run_source_leakage_audit():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    df_train = pd.read_parquet(data_dir / "train.parquet")
    df_test = pd.read_parquet(data_dir / "test.parquet")

    feature_cols = list(ML_INTRINSIC_FEATURE_NAMES)
    source_labels = sorted(df_train["source_id"].unique())
    source_to_idx = {s: i for i, s in enumerate(source_labels)}

    X_train = df_train[feature_cols].copy()
    y_train = df_train["source_id"].map(source_to_idx)
    groups_train = df_train["registrable_domain"]

    X_test = df_test[feature_cols].copy()
    y_test = df_test["source_id"].map(source_to_idx)

    # =========================================================================
    # EXPERIMENT 1: Full 34-Feature Source Classifier
    # =========================================================================
    print("Training 34-feature Source Classifier...")
    clf_source = HistGradientBoostingClassifier(max_iter=100, random_state=42, class_weight="balanced")
    clf_source.fit(X_train, y_train)

    y_pred_source = clf_source.predict(X_test)
    rep_source = classification_report(y_test, y_pred_source, target_names=source_labels, output_dict=True)
    cm_source = confusion_matrix(y_test, y_pred_source).tolist()

    # Feature importances via RandomForest on subsample or permutation
    print("Computing feature importance for source discrimination...")
    sub_sample = df_train.sample(n=min(10000, len(df_train)), random_state=42)
    rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, class_weight="balanced", n_jobs=-1)
    rf.fit(sub_sample[feature_cols], sub_sample["source_id"].map(source_to_idx))
    importances = sorted(
        zip(feature_cols, rf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )

    # =========================================================================
    # EXPERIMENT 2: Missingness / Sentinel-Only Source Classifier
    # =========================================================================
    print("Training Missingness-Only Source Classifier...")
    # Missingness indicators: 1 if feature is sentinel (-1.0, 0, or None), 0 otherwise
    # Sentinels in TrustLens schema: tls/cert sentinels are -1.0, domain_age_days is -1.0
    # Also check if value is 0.0 for counts/lengths
    missingness_cols = []
    X_train_miss = pd.DataFrame()
    X_test_miss = pd.DataFrame()

    for col in feature_cols:
        col_name = f"{col}_is_missing"
        # Features with sentinel -1.0:
        if "cert" in col or "tls" in col or "domain_age" in col:
            X_train_miss[col_name] = (X_train[col] == -1.0).astype(float)
            X_test_miss[col_name] = (X_test[col] == -1.0).astype(float)
        else:
            # For lexical/structural, missingness is zero length / zero count
            X_train_miss[col_name] = (X_train[col] == 0.0).astype(float)
            X_test_miss[col_name] = (X_test[col] == 0.0).astype(float)
        missingness_cols.append(col_name)

    clf_miss = HistGradientBoostingClassifier(max_iter=100, random_state=42, class_weight="balanced")
    clf_miss.fit(X_train_miss, y_train)

    y_pred_miss = clf_miss.predict(X_test_miss)
    rep_miss = classification_report(y_test, y_pred_miss, target_names=source_labels, output_dict=True)
    cm_miss = confusion_matrix(y_test, y_pred_miss).tolist()

    rf_miss = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, class_weight="balanced", n_jobs=-1)
    rf_miss.fit(X_train_miss.sample(n=min(10000, len(X_train_miss)), random_state=42), sub_sample["source_id"].map(source_to_idx))
    miss_importances = sorted(
        zip(missingness_cols, rf_miss.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )

    results = {
        "source_labels": source_labels,
        "full_source_classifier": {
            "accuracy": rep_source["accuracy"],
            "macro_f1": rep_source["macro avg"]["f1-score"],
            "weighted_f1": rep_source["weighted avg"]["f1-score"],
            "per_source_report": rep_source,
            "confusion_matrix": cm_source,
            "top_features_responsible": importances[:10],
        },
        "missingness_source_classifier": {
            "accuracy": rep_miss["accuracy"],
            "macro_f1": rep_miss["macro avg"]["f1-score"],
            "weighted_f1": rep_miss["weighted avg"]["f1-score"],
            "per_source_report": rep_miss,
            "confusion_matrix": cm_miss,
            "top_missingness_features_responsible": miss_importances[:10],
        },
    }

    out_file = audit_dir / "audit_02_source_leakage.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n=== SOURCE LEAKAGE AUDIT RESULTS ===")
    print(f"Full Feature Source Predictor Accuracy: {results['full_source_classifier']['accuracy']:.4f}")
    print(f"Full Feature Source Predictor Macro F1: {results['full_source_classifier']['macro_f1']:.4f}")
    print("\nTop 5 Source-Predicting Features:")
    for feat, imp in importances[:5]:
        print(f"  - {feat}: {imp:.4f}")

    print(f"\nMissingness-Only Source Predictor Accuracy: {results['missingness_source_classifier']['accuracy']:.4f}")
    print(f"Missingness-Only Source Predictor Macro F1: {results['missingness_source_classifier']['macro_f1']:.4f}")
    print("\nTop 5 Missingness-Predicting Features:")
    for feat, imp in miss_importances[:5]:
        print(f"  - {feat}: {imp:.4f}")


if __name__ == "__main__":
    run_source_leakage_audit()

