"""Phase 1 Audit: Baseline Reproduction & Metrics Verification.

Independently loads the active champion model artifacts and evaluates against
train, validation, and locked test partitions without modifying any model or data files.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure dependencies and sources are available
_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEPS_DIR = _ROOT / "intelligence" / "certificate_dataset" / ".deps"
_DATASET_SRC = _ROOT / "intelligence" / "certificate_dataset" / "src"
_ANALYZER_SRC = _ROOT / "intelligence" / "certificate_analyzer" / "src"

for p in [_DEPS_DIR, _DATASET_SRC, _ANALYZER_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import joblib
import numpy as np

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def main():
    print("=" * 70)
    print("PHASE 1: BASELINE REPRODUCTION & METRICS VERIFICATION")
    print("=" * 70)

    artifacts_dir = _ANALYZER_SRC / "certificate_analyzer" / "ml" / "artifacts"
    champion_path = artifacts_dir / "champion_model.joblib"
    anomaly_path = artifacts_dir / "anomaly_detector.joblib"
    manifest_path = artifacts_dir / "model_manifest.json"

    print(f"Artifact directory: {artifacts_dir}")
    print(f"Champion exists: {champion_path.exists()}")
    print(f"Anomaly detector exists: {anomaly_path.exists()}")
    print(f"Manifest exists: {manifest_path.exists()}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    champion = joblib.load(champion_path)
    _ = joblib.load(anomaly_path)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES

    results = {}
    dfs = {}

    for split_name in ["train", "val", "test"]:
        df = dataset_loader.extract_tabular_features(splits[split_name], labels_map)
        dfs[split_name] = df
        X = df[feature_cols]
        y_true = df["target"].to_numpy()

        preds = champion.predict(X)
        probs = champion.predict_proba(X)[:, 1]

        metrics = CertificateMLEvaluator.evaluate(y_true, preds, probs)
        results[split_name] = {
            "sample_count": len(df),
            "positive_count": int(df["target"].sum()),
            "negative_count": int(len(df) - df["target"].sum()),
            "metrics": metrics,
        }

        print(f"\n--- Split: {split_name.upper()} (N={len(df)}) ---")
        print(f"Positives: {results[split_name]['positive_count']}, Negatives: {results[split_name]['negative_count']}")
        print(f"Accuracy:    {metrics['accuracy']:.6f}")
        print(f"Macro F1:    {metrics['macro_f1']:.6f}")
        print(f"Weighted F1: {metrics['weighted_f1']:.6f}")
        print(f"Precision:   {metrics['precision']:.6f}")
        print(f"Recall:      {metrics['recall']:.6f}")
        print(f"ROC-AUC:     {metrics['roc_auc']:.8f}")
        print(f"PR-AUC:      {metrics['pr_auc']:.8f}")
        print(f"Brier Score: {metrics['brier_score']:.8e}")
        print(f"Confusion Matrix: {metrics['confusion_matrix']}")

    # Verify against manifest
    print("\n--- Manifest Comparison ---")
    manifest_train = manifest["champion_metrics"]["train"]
    manifest_val = manifest["champion_metrics"]["validation"]
    manifest_test = manifest["champion_metrics"]["locked_test"]

    train_match = (results["train"]["metrics"]["accuracy"] == manifest_train["accuracy"]) and \
                  (results["train"]["metrics"]["macro_f1"] == manifest_train["macro_f1"])
    val_match = (results["val"]["metrics"]["accuracy"] == manifest_val["accuracy"]) and \
                (results["val"]["metrics"]["macro_f1"] == manifest_val["macro_f1"])
    test_match = (abs(results["test"]["metrics"]["accuracy"] - manifest_test["accuracy"]) < 1e-6) and \
                 (abs(results["test"]["metrics"]["macro_f1"] - manifest_test["macro_f1"]) < 1e-6)

    print(f"Train metrics match manifest:      {train_match}")
    print(f"Validation metrics match manifest: {val_match}")
    print(f"Test metrics match manifest:       {test_match}")

    # Inspect the single False Positive in locked test set
    df_test = dfs["test"]
    X_test = df_test[feature_cols]
    y_test = df_test["target"].to_numpy()
    preds_test = champion.predict(X_test)
    probs_test = champion.predict_proba(X_test)[:, 1]

    fp_indices = np.where((y_test == 0) & (preds_test == 1))[0]
    print(f"\nNumber of False Positives in locked test: {len(fp_indices)}")

    fp_details = []
    for idx in fp_indices:
        fp_row = df_test.iloc[idx].to_dict()
        fp_prob = float(probs_test[idx])
        fp_fp = fp_row["fingerprint"]
        fp_lbls = labels_map.get(fp_fp, {})
        print(f"\nFalse Positive Sample Fingerprint: {fp_fp}")
        print(f"Predicted Probability: {fp_prob:.6f}")
        print(f"Features: validity_days={fp_row['validity_duration_days']}, key_algo={fp_row['key_algorithm']}, key_size={fp_row['key_size_bits']}, sig_algo={fp_row['signature_algorithm']}")
        print(f"Labels assigned: {fp_lbls}")
        fp_details.append({
            "fingerprint": fp_fp,
            "probability": fp_prob,
            "row": {k: v for k, v in fp_row.items() if k not in ["fingerprint", "spki"]},
            "labels": fp_lbls,
        })

    # Save Phase 1 results
    output_path = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase1_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "train": results["train"],
            "val": results["val"],
            "test": results["test"],
            "matches_manifest": {
                "train": train_match,
                "val": val_match,
                "test": test_match,
            },
            "false_positives_test": fp_details,
        }, f, indent=2)
    print(f"\nPhase 1 output saved to {output_path}")


if __name__ == "__main__":
    main()
