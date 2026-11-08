"""Phase 9 Audit: Metric Correctness Verification & Baseline Comparison.

1. Benchmarks champion against Dummy Classifiers (Majority Class, Stratified Random).
2. Verifies confusion matrix mathematical invariants.
3. Computes Precision-Recall and ROC curves across decision thresholds.
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
from sklearn.dummy import DummyClassifier

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def main():
    print("=" * 70)
    print("PHASE 9: METRIC CORRECTNESS VERIFICATION & BASELINES")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    df_test = dataset_loader.extract_tabular_features(splits["test"], labels_map)

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_train, y_train = df_train[feature_cols], df_train["target"].to_numpy()
    X_test, y_test = df_test[feature_cols], df_test["target"].to_numpy()

    champion_path = _ANALYZER_SRC / "certificate_analyzer" / "ml" / "artifacts" / "champion_model.joblib"
    champion = joblib.load(champion_path)

    # 1. Champion Model Performance
    champ_preds = champion.predict(X_test)
    champ_probs = champion.predict_proba(X_test)[:, 1]
    champ_metrics = CertificateMLEvaluator.evaluate(y_test, champ_preds, champ_probs)

    # Invariant checks
    cm = champ_metrics["confusion_matrix"]
    total_cm = cm["true_negative"] + cm["false_positive"] + cm["false_negative"] + cm["true_positive"]
    assert total_cm == len(y_test), f"Confusion matrix total {total_cm} != sample count {len(y_test)}"

    # 2. Dummy Majority Classifier (always predicts 1)
    dummy_majority = DummyClassifier(strategy="most_frequent")
    dummy_majority.fit(X_train, y_train)
    maj_preds = dummy_majority.predict(X_test)
    maj_probs = dummy_majority.predict_proba(X_test)[:, 1]
    maj_metrics = CertificateMLEvaluator.evaluate(y_test, maj_preds, maj_probs)

    # 3. Dummy Stratified Classifier (samples from prior distribution)
    dummy_strat = DummyClassifier(strategy="stratified", random_state=42)
    dummy_strat.fit(X_train, y_train)
    strat_preds = dummy_strat.predict(X_test)
    strat_probs = dummy_strat.predict_proba(X_test)[:, 1]
    strat_metrics = CertificateMLEvaluator.evaluate(y_test, strat_preds, strat_probs)

    print("\n--- Baseline Model Comparison on Locked Test Set ---")
    print(f"{'Model Architecture':<30} | {'Accuracy':<10} | {'Macro F1':<10} | {'Weighted F1':<11} | ROC-AUC")
    print("-" * 80)
    print(f"{'Dummy Majority (Class 1)':<30} | {maj_metrics['accuracy']:<10.4f} | {maj_metrics['macro_f1']:<10.4f} | {maj_metrics['weighted_f1']:<11.4f} | {maj_metrics.get('roc_auc')}")
    print(f"{'Dummy Stratified Random':<30} | {strat_metrics['accuracy']:<10.4f} | {strat_metrics['macro_f1']:<10.4f} | {strat_metrics['weighted_f1']:<11.4f} | {strat_metrics.get('roc_auc'):.4f}")
    print(f"{'Champion (Logistic Regression)':<30} | {champ_metrics['accuracy']:<10.4f} | {champ_metrics['macro_f1']:<10.4f} | {champ_metrics['weighted_f1']:<11.4f} | {champ_metrics.get('roc_auc'):.6f}")

    # Sample points across threshold sweep
    sample_thresholds = [0.1, 0.3, 0.5, 0.7, 0.9]
    thresh_table = []
    print("\n--- Decision Threshold Sensitivity on Champion Model ---")
    print(f"{'Threshold':<10} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'Macro F1':<10} | CM (TN, FP, FN, TP)")
    print("-" * 85)
    for t in sample_thresholds:
        t_preds = (champ_probs >= t).astype(int)
        m = CertificateMLEvaluator.evaluate(y_test, t_preds)
        cm_str = f"({m['confusion_matrix']['true_negative']}, {m['confusion_matrix']['false_positive']}, {m['confusion_matrix']['false_negative']}, {m['confusion_matrix']['true_positive']})"
        print(f"{t:<10.2f} | {m['accuracy']:<10.4f} | {m['precision']:<10.4f} | {m['recall']:<10.4f} | {m['macro_f1']:<10.4f} | {cm_str}")
        thresh_table.append({
            "threshold": t,
            "metrics": m,
        })

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase9_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "champion_metrics": champ_metrics,
            "dummy_majority_metrics": maj_metrics,
            "dummy_stratified_metrics": strat_metrics,
            "threshold_sweep": thresh_table,
        }, f, indent=2)

    print(f"\nPhase 9 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
