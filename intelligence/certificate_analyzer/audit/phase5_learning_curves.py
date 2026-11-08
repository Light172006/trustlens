"""Phase 5 Audit: Overfitting Analysis & Learning Curves.

Evaluates training and validation metrics across increasing fractions of the training split
(10%, 25%, 50%, 75%, 100%) to measure sample complexity, saturation, and generalization gap.
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

import numpy as np

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def main():
    print("=" * 70)
    print("PHASE 5: OVERFITTING ANALYSIS & LEARNING CURVES")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    df_val = dataset_loader.extract_tabular_features(splits["val"], labels_map)

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_val = df_val[feature_cols]
    y_val = df_val["target"].to_numpy()

    fractions = [0.10, 0.25, 0.50, 0.75, 1.00]
    curve_records = []

    print(f"{'Fraction':<10} | {'Train N':<8} | {'Train Acc':<10} | {'Val Acc':<10} | {'Train F1':<10} | {'Val F1':<10} | {'Gap (Train-Val F1)'}")
    print("-" * 80)

    # Use fixed seed for deterministic sampling
    rng = np.random.RandomState(42)

    for frac in fractions:
        n_samples = int(len(df_train) * frac)
        sample_indices = rng.choice(len(df_train), size=n_samples, replace=False)
        sub_train = df_train.iloc[sample_indices]

        X_tr = sub_train[feature_cols]
        y_tr = sub_train["target"].to_numpy()

        pipeline = CertificateModelFactory.get_candidate_models()["logistic_regression"]
        pipeline.fit(X_tr, y_tr)

        tr_preds = pipeline.predict(X_tr)
        tr_probs = pipeline.predict_proba(X_tr)[:, 1]
        tr_m = CertificateMLEvaluator.evaluate(y_tr, tr_preds, tr_probs)

        va_preds = pipeline.predict(X_val)
        va_probs = pipeline.predict_proba(X_val)[:, 1]
        va_m = CertificateMLEvaluator.evaluate(y_val, va_preds, va_probs)

        gap = float(tr_m["macro_f1"] - va_m["macro_f1"])

        rec = {
            "fraction": frac,
            "train_samples": n_samples,
            "train_accuracy": tr_m["accuracy"],
            "val_accuracy": va_m["accuracy"],
            "train_macro_f1": tr_m["macro_f1"],
            "val_macro_f1": va_m["macro_f1"],
            "train_roc_auc": tr_m.get("roc_auc"),
            "val_roc_auc": va_m.get("roc_auc"),
            "generalization_gap": gap,
        }
        curve_records.append(rec)

        print(f"{frac*100:>7.0f}%   | {n_samples:<8} | {tr_m['accuracy']:<10.4f} | {va_m['accuracy']:<10.4f} | {tr_m['macro_f1']:<10.4f} | {va_m['macro_f1']:<10.4f} | {gap:+.6f}")

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase5_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"learning_curve": curve_records}, f, indent=2)

    print(f"\nPhase 5 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
