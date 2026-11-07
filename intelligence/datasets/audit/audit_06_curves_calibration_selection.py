"""Audit Module 6: Learning Curves, Calibration Integrity, and Model Selection Audit.

1. Evaluates learning curves across 10%, 25%, 50%, 75%, 100% training subsets.
2. Computes Expected Calibration Error (ECE), reliability diagram bins, and Brier score.
3. Audits model comparison methodology and test set contamination in model selection.
"""

import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import brier_score_loss, f1_score, precision_recall_fscore_support

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES


def compute_ece(y_true: np.ndarray, y_proba: np.ndarray, n_bins: int = 10) -> tuple[float, float, list[dict]]:
    """Compute Expected Calibration Error (ECE) and reliability bin statistics."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    mce = 0.0
    bins_data = []

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        mask = (y_proba >= low) & (y_proba < high) if i < n_bins - 1 else (y_proba >= low) & (y_proba <= high)
        count = int(mask.sum())
        if count > 0:
            bin_acc = float(y_true[mask].mean())
            bin_conf = float(y_proba[mask].mean())
            gap = abs(bin_acc - bin_conf)
            ece += (count / len(y_true)) * gap
            mce = max(mce, gap)
            bins_data.append({
                "bin_range": [round(low, 2), round(high, 2)],
                "count": count,
                "empirical_accuracy": round(bin_acc, 4),
                "mean_confidence": round(bin_conf, 4),
                "calibration_gap": round(gap, 4),
            })
        else:
            bins_data.append({
                "bin_range": [round(low, 2), round(high, 2)],
                "count": 0,
                "empirical_accuracy": 0.0,
                "mean_confidence": 0.0,
                "calibration_gap": 0.0,
            })

    return float(ece), float(mce), bins_data


def run_curves_and_calibration_audit():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    df_train = pd.read_parquet(data_dir / "train.parquet")
    df_val = pd.read_parquet(data_dir / "val.parquet")
    df_test = pd.read_parquet(data_dir / "test.parquet")

    feature_cols = list(ML_INTRINSIC_FEATURE_NAMES)
    X_val = df_val[feature_cols].copy()
    y_val = df_val["binary_label"].values
    X_test = df_test[feature_cols].copy()
    y_test = df_test["binary_label"].values

    # =========================================================================
    # PART 1: Grouped Learning Curves (10%, 25%, 50%, 75%, 100%)
    # =========================================================================
    print("Computing Learning Curves across 10%, 25%, 50%, 75%, 100% data fractions...")
    fractions = [0.10, 0.25, 0.50, 0.75, 1.00]
    learning_curve_data = []

    unique_domains = df_train["registrable_domain"].unique()
    rng = np.random.RandomState(42)
    shuffled_domains = rng.permutation(unique_domains)

    for frac in fractions:
        domain_cutoff = int(len(shuffled_domains) * frac)
        selected_domains = set(shuffled_domains[:domain_cutoff])
        sub_train = df_train[df_train["registrable_domain"].isin(selected_domains)]

        X_sub = sub_train[feature_cols]
        y_sub = sub_train["binary_label"].values

        clf = HistGradientBoostingClassifier(
            max_iter=150,
            random_state=42,
            class_weight="balanced",
            early_stopping=True,
            n_iter_no_change=10,
        )
        clf.fit(X_sub, y_sub)

        # Train metrics
        pred_train = clf.predict(X_sub)
        train_acc = float((pred_train == y_sub).mean())
        train_f1 = float(f1_score(y_sub, pred_train, average="macro"))

        # Val metrics
        pred_val = clf.predict(X_val)
        val_acc = float((pred_val == y_val).mean())
        val_f1 = float(f1_score(y_val, pred_val, average="macro"))

        # Test metrics
        pred_test = clf.predict(X_test)
        test_acc = float((pred_test == y_test).mean())
        test_f1 = float(f1_score(y_test, pred_test, average="macro"))

        gap = train_f1 - val_f1

        learning_curve_data.append({
            "training_fraction": frac,
            "training_samples": len(sub_train),
            "training_domains": len(selected_domains),
            "train_accuracy": round(train_acc, 4),
            "train_macro_f1": round(train_f1, 4),
            "val_accuracy": round(val_acc, 4),
            "val_macro_f1": round(val_f1, 4),
            "test_accuracy": round(test_acc, 4),
            "test_macro_f1": round(test_f1, 4),
            "generalization_gap": round(gap, 4),
        })
        print(f"  Frac {frac*100:3.0f}% ({len(sub_train):6d} samples) -> Train F1: {train_f1:.4f}, Val F1: {val_f1:.4f}, Gap: {gap:.4f}")

    # =========================================================================
    # PART 2: Calibration Integrity and Reliability Diagram
    # =========================================================================
    print("\nAuditing Probability Calibration on Untouched Holdout Test Set...")
    artifact_path = repo_root / "trustlens_intelligence" / "evaluation" / "artifacts" / "baseline_classifier.joblib"
    artifact = joblib.load(artifact_path)
    model = artifact["model"]

    test_probas = model.predict_proba(X_test)[:, 1]
    brier = float(brier_score_loss(y_test, test_probas))
    ece, mce, bins_data = compute_ece(y_test, test_probas, n_bins=10)

    # Probability distribution sharpness check
    pct_extremes = float(((test_probas < 0.05) | (test_probas > 0.95)).mean() * 100)

    # =========================================================================
    # PART 3: Model Selection Validity Audit
    # =========================================================================
    # Check lines of train_tier2.py: Candidate A and B were both evaluated on X_test, y_test
    selection_audit = {
        "selection_dataset": "test_partition (X_test, y_test)",
        "intended_holdout": "test_partition",
        "leakage_finding": "Test partition was used as the model selection decision criterion. "
                           "Candidate A (Logistic Regression) and Candidate B (HistGradientBoosting) were ranked "
                           "directly on test F1 and test PR-AUC. The test partition was contaminated as a development validation set.",
        "recommendation": "Use val.parquet for hyperparameter tuning and model selection; hold test.parquet as an untouched single-evaluation set.",
    }

    results = {
        "learning_curves": learning_curve_data,
        "calibration_audit": {
            "brier_score": round(brier, 4),
            "expected_calibration_error": round(ece, 4),
            "maximum_calibration_error": round(mce, 4),
            "pct_probabilities_at_extremes": round(pct_extremes, 2),
            "reliability_diagram_bins": bins_data,
        },
        "model_selection_validity": selection_audit,
    }

    out_file = audit_dir / "audit_06_curves_calibration.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n=== CALIBRATION & SELECTION AUDIT SUMMARY ===")
    print(f"Reported Brier Score: {brier:.4f}")
    print(f"Expected Calibration Error (ECE): {ece:.4f}")
    print(f"Maximum Calibration Error (MCE): {mce:.4f}")
    print(f"Percentage of Predictions at Extremes (<0.05 or >0.95): {pct_extremes:.2f}%")
    print(f"Model Selection Issue: {selection_audit['leakage_finding']}")


if __name__ == "__main__":
    run_curves_and_calibration_audit()

