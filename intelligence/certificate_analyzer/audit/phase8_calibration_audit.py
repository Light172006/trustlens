"""Phase 8 Audit: Calibration Audit & Probability Reliability.

Evaluates:
1. Brier score loss.
2. Expected Calibration Error (ECE) across 10 equal bins.
3. Reliability table (confidence vs empirical accuracy per bin).
4. Probability distribution shape (sharpness / overconfidence analysis).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_DEPS_DIR = _ROOT / "intelligence" / "certificate_dataset" / ".deps"
_DATASET_SRC = _ROOT / "intelligence" / "certificate_dataset" / "src"
_ANALYZER_SRC = _ROOT / "intelligence" / "certificate_analyzer" / "src"

for p in [_DEPS_DIR, _DATASET_SRC, _ANALYZER_SRC]:
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import joblib
import numpy as np
from sklearn.metrics import brier_score_loss

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10):
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bin_assignments = np.digitize(y_prob, bin_edges) - 1
    # Clip any 1.0 edge to the last bin
    bin_assignments = np.clip(bin_assignments, 0, n_bins - 1)

    ece = 0.0
    total_samples = len(y_true)
    table = []

    for b in range(n_bins):
        mask = (bin_assignments == b)
        count = int(np.sum(mask))
        if count > 0:
            avg_prob = float(np.mean(y_prob[mask]))
            empirical_acc = float(np.mean(y_true[mask]))
            abs_diff = abs(empirical_acc - avg_prob)
            ece += (count / total_samples) * abs_diff
        else:
            avg_prob = float((bin_edges[b] + bin_edges[b + 1]) / 2.0)
            empirical_acc = 0.0
            abs_diff = 0.0

        table.append({
            "bin_index": b + 1,
            "bin_range": f"[{bin_edges[b]:.1f}, {bin_edges[b+1]:.1f})",
            "sample_count": count,
            "mean_predicted_prob": avg_prob,
            "empirical_accuracy": empirical_acc,
            "calibration_gap": abs_diff,
        })

    return ece, table


def main():
    print("=" * 70)
    print("PHASE 8: CALIBRATION AUDIT & PROBABILITY RELIABILITY")
    print("=" * 70)

    champion_path = _ANALYZER_SRC / "certificate_analyzer" / "ml" / "artifacts" / "champion_model.joblib"
    champion_pipeline = joblib.load(champion_path)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_test = dataset_loader.extract_tabular_features(splits["test"], labels_map)
    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_test = df_test[feature_cols]
    y_test = df_test["target"].to_numpy()

    probs = champion_pipeline.predict_proba(X_test)[:, 1]
    brier = float(brier_score_loss(y_test, probs))
    ece, rel_table = compute_ece(y_test, probs, n_bins=10)

    print(f"Locked Test Set Samples: {len(y_test)}")
    print(f"Brier Score Loss:        {brier:.8e}")
    print(f"Expected Calibration Error (ECE): {ece*100:.4f}% ({ece:.6f})")

    print("\n--- Reliability Diagram Table (10 Bins) ---")
    print(f"{'Bin':<5} | {'Range':<12} | {'Count':<8} | {'Mean Pred Prob':<16} | {'Empirical Acc':<15} | Gap")
    print("-" * 75)
    for row in rel_table:
        print(f"{row['bin_index']:<5} | {row['bin_range']:<12} | {row['sample_count']:<8} | {row['mean_predicted_prob']:<16.4f} | {row['empirical_accuracy']:<15.4f} | {row['calibration_gap']:.4f}")

    # Measure Sharpness: proportion of samples with prob < 0.05 or prob > 0.95
    p_extreme_low = int(np.sum(probs < 0.05))
    p_extreme_high = int(np.sum(probs > 0.95))
    p_uncertain = int(np.sum((probs >= 0.05) & (probs <= 0.95)))
    sharpness = float((p_extreme_low + p_extreme_high) / len(probs))

    print("\n--- Probability Sharpness Analysis ---")
    print(f"Extreme Low Confidence  (P < 0.05): {p_extreme_low} ({p_extreme_low/len(probs)*100:.2f}%)")
    print(f"Extreme High Confidence (P > 0.95): {p_extreme_high} ({p_extreme_high/len(probs)*100:.2f}%)")
    print(f"Uncertain Zone (0.05 <= P <= 0.95): {p_uncertain} ({p_uncertain/len(probs)*100:.2f}%)")
    print(f"Total Sharp Decisions:               {sharpness*100:.2f}%")

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase8_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "brier_score": brier,
            "expected_calibration_error": ece,
            "reliability_table": rel_table,
            "sharpness": {
                "extreme_low": p_extreme_low,
                "extreme_high": p_extreme_high,
                "uncertain": p_uncertain,
                "sharpness_ratio": sharpness,
            }
        }, f, indent=2)

    print(f"\nPhase 8 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
