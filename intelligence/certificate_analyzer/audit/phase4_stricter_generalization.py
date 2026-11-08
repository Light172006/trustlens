"""Phase 4 Audit: Stricter Generalization Experiments.

1. Issuer-Held-Out Evaluation (GroupKFold on issuer_dn).
   Verifies whether the classifier generalizes to completely unseen Certificate Authorities.
2. Chronological Holdout Evaluation.
   Evaluates model performance across historical vs recent temporal horizons.
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
from sklearn.model_selection import GroupKFold

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def run_issuer_held_out(dataset_loader, labels_map, splits, n_splits=5):
    print("\n--- 1. Issuer-Held-Out Evaluation (GroupKFold on issuer_dn) ---")
    train_records = splits["train"]
    # Extract tabular features plus issuer_dn
    rows = []
    for r in train_records:
        iss = r.get("issuer_dn") or "UNKNOWN_ISSUER"
        rows.append(iss)

    df_train = dataset_loader.extract_tabular_features(train_records, labels_map)
    df_train["issuer_dn"] = rows

    print(f"Total training samples: {len(df_train)}")
    print(f"Unique Issuers in train: {df_train['issuer_dn'].nunique()}")

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X = df_train[feature_cols]
    y = df_train["target"].to_numpy()
    groups = df_train["issuer_dn"].to_numpy()

    gkf = GroupKFold(n_splits=n_splits)
    fold_metrics = []

    for fold, (tr_idx, va_idx) in enumerate(gkf.split(X, y, groups=groups), 1):
        X_tr, y_tr = X.iloc[tr_idx], y[tr_idx]
        X_va, y_va = X.iloc[va_idx], y[va_idx]

        iss_tr = set(groups[tr_idx])
        iss_va = set(groups[va_idx])
        assert len(iss_tr & iss_va) == 0, f"Issuer leakage in fold {fold}"

        pipeline = CertificateModelFactory.get_candidate_models()["logistic_regression"]
        pipeline.fit(X_tr, y_tr)

        preds = pipeline.predict(X_va)
        probs = pipeline.predict_proba(X_va)[:, 1]

        m = CertificateMLEvaluator.evaluate(y_va, preds, probs)
        m["fold"] = fold
        m["unseen_issuers_count"] = len(iss_va)
        m["val_size"] = len(va_idx)
        m["val_positives"] = int(y_va.sum())
        m["val_negatives"] = int(len(y_va) - y_va.sum())
        fold_metrics.append(m)

        print(f"Fold {fold} ({len(iss_va)} unseen CAs, {len(va_idx)} certs): "
              f"Acc={m['accuracy']:.6f}, Macro-F1={m['macro_f1']:.6f}, "
              f"ROC-AUC={m.get('roc_auc')}, Brier={m.get('brier_score'):.6e}, CM={m['confusion_matrix']}")

    # Aggregate
    agg = {}
    for k in ["accuracy", "macro_f1", "weighted_f1", "precision", "recall", "roc_auc", "brier_score"]:
        vals = [fm[k] for fm in fold_metrics if fm[k] is not None]
        agg[k] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals)),
            "min": float(np.min(vals)),
            "max": float(np.max(vals)),
        }

    return {"folds": fold_metrics, "aggregate": agg}


def run_chronological_holdout(dataset_loader, labels_map):
    print("\n--- 2. Chronological Holdout Evaluation ---")
    splits_chrono = dataset_loader.load_split_records(split_type="chronological")

    df_tr = dataset_loader.extract_tabular_features(splits_chrono["train"], labels_map)
    df_va = dataset_loader.extract_tabular_features(splits_chrono["val"], labels_map)
    df_te = dataset_loader.extract_tabular_features(splits_chrono["test"], labels_map)

    print(f"Chrono Train (Historical): {len(df_tr)} certs (Pos={df_tr['target'].sum()}, Neg={len(df_tr)-df_tr['target'].sum()})")
    print(f"Chrono Val:               {len(df_va)} certs (Pos={df_va['target'].sum()}, Neg={len(df_va)-df_va['target'].sum()})")
    print(f"Chrono Test (Future):      {len(df_te)} certs (Pos={df_te['target'].sum()}, Neg={len(df_te)-df_te['target'].sum()})")

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_tr, y_tr = df_tr[feature_cols], df_tr["target"].to_numpy()
    X_va, y_va = df_va[feature_cols], df_va["target"].to_numpy()
    X_te, y_te = df_te[feature_cols], df_te["target"].to_numpy()

    pipeline = CertificateModelFactory.get_candidate_models()["logistic_regression"]
    pipeline.fit(X_tr, y_tr)

    # Evaluate on Chrono Val
    preds_va = pipeline.predict(X_va)
    probs_va = pipeline.predict_proba(X_va)[:, 1]
    m_va = CertificateMLEvaluator.evaluate(y_va, preds_va, probs_va)

    # Evaluate on Chrono Test (Future Horizon)
    preds_te = pipeline.predict(X_te)
    probs_te = pipeline.predict_proba(X_te)[:, 1]
    m_te = CertificateMLEvaluator.evaluate(y_te, preds_te, probs_te)

    print(f"\nChronological Val:  Acc={m_va['accuracy']:.6f}, Macro-F1={m_va['macro_f1']:.6f}, ROC-AUC={m_va.get('roc_auc')}, CM={m_va['confusion_matrix']}")
    print(f"Chronological Test: Acc={m_te['accuracy']:.6f}, Macro-F1={m_te['macro_f1']:.6f}, ROC-AUC={m_te.get('roc_auc')}, CM={m_te['confusion_matrix']}")

    return {
        "val": m_va,
        "test": m_te,
    }


def main():
    print("=" * 70)
    print("PHASE 4: STRICTER GENERALIZATION EXPERIMENTS")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits_spki = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    issuer_results = run_issuer_held_out(dataset_loader, labels_map, splits_spki, n_splits=5)
    chrono_results = run_chronological_holdout(dataset_loader, labels_map)

    results = {
        "issuer_held_out": issuer_results,
        "chronological_holdout": chrono_results,
    }

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase4_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nPhase 4 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
