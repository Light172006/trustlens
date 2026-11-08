"""Phase 3 Audit: 5-Fold StratifiedGroupKFold Cross-Validation on Training Partition.

Evaluates candidate Logistic Regression architecture across 5 folds grouped by SPKI
and stratified by target label using multiple random seeds (42, 123, 2026).
Locked test partition is strictly untouched.
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
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def run_cross_validation(df_train: pd.DataFrame, seeds=(42, 123, 2026), n_splits=5):
    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X = df_train[feature_cols]
    y = df_train["target"].to_numpy()
    groups = df_train["spki"].to_numpy()

    all_seed_results = {}

    for seed in seeds:
        print(f"\n================ Running 5-Fold StratifiedGroupKFold (Seed: {seed}) ================")
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)

        fold_metrics = []
        for fold, (train_idx, val_idx) in enumerate(sgkf.split(X, y, groups=groups), 1):
            X_tr, y_tr = X.iloc[train_idx], y[train_idx]
            X_va, y_va = X.iloc[val_idx], y[val_idx]
            groups_tr = set(groups[train_idx])
            groups_va = set(groups[val_idx])

            # Verify 0 group leakage
            leakage = len(groups_tr & groups_va)
            assert leakage == 0, f"SPKI group leakage detected in fold {fold}: {leakage} shared keys"

            # Create fresh candidate pipeline
            pipeline = CertificateModelFactory.get_candidate_models()["logistic_regression"]
            pipeline.fit(X_tr, y_tr)

            preds = pipeline.predict(X_va)
            probs = pipeline.predict_proba(X_va)[:, 1]

            m = CertificateMLEvaluator.evaluate(y_va, preds, probs)
            m["fold"] = fold
            m["train_size"] = len(train_idx)
            m["val_size"] = len(val_idx)
            m["val_positives"] = int(y_va.sum())
            m["val_negatives"] = int(len(y_va) - y_va.sum())
            fold_metrics.append(m)

            print(f"Fold {fold}: Val Acc={m['accuracy']:.6f}, Macro-F1={m['macro_f1']:.6f}, ROC-AUC={m['roc_auc']:.6f}, Brier={m['brier_score']:.6e}, CM={m['confusion_matrix']}")

        # Aggregate across folds
        keys = ["accuracy", "macro_f1", "weighted_f1", "precision", "recall", "roc_auc", "pr_auc", "brier_score"]
        agg = {}
        for k in keys:
            vals = [fm[k] for fm in fold_metrics if fm[k] is not None]
            agg[k] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals)),
            }

        all_seed_results[str(seed)] = {
            "folds": fold_metrics,
            "aggregate": agg,
        }

        print(f"\n--- Seed {seed} Aggregate Summary ---")
        for k in ["accuracy", "macro_f1", "roc_auc", "brier_score"]:
            print(f"{k.upper():<12}: Mean={agg[k]['mean']:.6f} +/- {agg[k]['std']:.6f} (Min={agg[k]['min']:.6f}, Max={agg[k]['max']:.6f})")

    return all_seed_results


def main():
    print("=" * 70)
    print("PHASE 3: 5-FOLD STRATIFIED GROUP K-FOLD CROSS-VALIDATION")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    # ONLY training split is used
    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    print(f"Training partition size: {len(df_train)} records, {df_train['spki'].nunique()} unique SPKIs")
    print(f"Class distribution: {df_train['target'].sum()} Positive (Compliant), {len(df_train) - df_train['target'].sum()} Negative (Non-Compliant)")

    cv_results = run_cross_validation(df_train, seeds=[42, 123, 2026], n_splits=5)

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase3_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(cv_results, f, indent=2)

    print(f"\nPhase 3 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()

