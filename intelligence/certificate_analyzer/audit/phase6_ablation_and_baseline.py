"""Phase 6 Audit: Feature Ablation & Deterministic Rule Baseline Agreement.

1. Systematically ablates feature subsets to quantify contribution of each feature to policy classification.
2. Measures exact agreement and Cohen's Kappa between ML predictions and the deterministic CA/B Forum rule baseline.
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
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import cohen_kappa_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.evaluation import CertificateMLEvaluator
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def run_ablation(df_train: pd.DataFrame, df_test: pd.DataFrame):
    print("\n--- 1. Systematic Feature Ablation Experiments ---")

    ablation_configs = {
        "all_features": {
            "num": NUMERIC_FEATURES,
            "cat": CATEGORICAL_FEATURES,
            "description": "Full feature set (12 numeric, 3 categorical)",
        },
        "without_validity_duration": {
            "num": [f for f in NUMERIC_FEATURES if f != "validity_duration_days"],
            "cat": CATEGORICAL_FEATURES,
            "description": "Ablated: validity_duration_days removed",
        },
        "without_key_size_bits": {
            "num": [f for f in NUMERIC_FEATURES if f != "key_size_bits"],
            "cat": CATEGORICAL_FEATURES,
            "description": "Ablated: key_size_bits removed",
        },
        "without_key_usage_count": {
            "num": [f for f in NUMERIC_FEATURES if f != "key_usage_count"],
            "cat": CATEGORICAL_FEATURES,
            "description": "Ablated: key_usage_count removed",
        },
        "without_san_count": {
            "num": [f for f in NUMERIC_FEATURES if f != "san_count"],
            "cat": CATEGORICAL_FEATURES,
            "description": "Ablated: san_count removed",
        },
        "non_rule_structural_only": {
            "num": [
                "san_count", "is_wildcard", "has_scts", "sct_count",
                "extension_count", "key_usage_count", "extended_key_usage_count",
                "is_ca", "is_self_signed", "subject_dn_length"
            ],
            "cat": [],
            "description": "Ablated: Non-rule structural features only (pure extensions/counts)",
        },
    }

    results = {}
    print(f"{'Condition':<28} | {'Val Acc':<9} | {'Val F1':<9} | {'Val ROC-AUC':<11} | Description")
    print("-" * 85)

    y_train = df_train["target"].to_numpy()
    y_test = df_test["target"].to_numpy()

    for cond_name, cfg in ablation_configs.items():
        num_cols = cfg["num"]
        cat_cols = cfg["cat"]

        transformers = []
        if num_cols:
            transformers.append(("num", StandardScaler(), num_cols))
        if cat_cols:
            transformers.append(("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols))

        preprocessor = ColumnTransformer(transformers=transformers, remainder="drop")
        pipeline = Pipeline([
            ("preprocessor", preprocessor),
            ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
        ])

        cols_needed = num_cols + cat_cols
        pipeline.fit(df_train[cols_needed], y_train)

        preds = pipeline.predict(df_test[cols_needed])
        probs = pipeline.predict_proba(df_test[cols_needed])[:, 1]
        m = CertificateMLEvaluator.evaluate(y_test, preds, probs)

        results[cond_name] = {
            "description": cfg["description"],
            "metrics": m,
        }

        print(f"{cond_name:<28} | {m['accuracy']:<9.4f} | {m['macro_f1']:<9.4f} | {m.get('roc_auc', 0.0):<11.4f} | {cfg['description']}")

    return results


def run_rule_baseline_comparison(df_test: pd.DataFrame, champion_pipeline):
    print("\n--- 2. Deterministic CA/B Forum Rule Baseline Comparison ---")

    # Pure deterministic CA/B Forum BR v2.0.8 rule engine logic:
    # 1. Validity duration <= 399 days (398d + 1d grace)
    # 2. RSA key >= 2048 bits (ECC always allowed)
    # 3. Signature digest not MD5 or SHA-1
    deterministic_preds = []
    for _, row in df_test.iterrows():
        val_days = row["validity_duration_days"]
        key_algo = str(row["key_algorithm"]).upper()
        key_bits = row["key_size_bits"]
        sig_algo = str(row["signature_algorithm"]).lower()

        val_ok = (val_days <= 399.0)
        key_ok = (key_bits >= 2048) if key_algo == "RSA" else True
        sig_ok = ("sha1" not in sig_algo) and ("md5" not in sig_algo)

        rule_verdict = 1 if (val_ok and key_ok and sig_ok) else 0
        deterministic_preds.append(rule_verdict)

    deterministic_preds = np.array(deterministic_preds)
    y_ground_truth = df_test["target"].to_numpy()

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    ml_preds = champion_pipeline.predict(df_test[feature_cols])

    # Rule baseline vs Ground Truth
    rule_vs_gt = CertificateMLEvaluator.evaluate(y_ground_truth, deterministic_preds)
    ml_vs_gt = CertificateMLEvaluator.evaluate(y_ground_truth, ml_preds)

    # ML vs Rule Baseline
    agreement_count = int(np.sum(ml_preds == deterministic_preds))
    disagreement_count = int(np.sum(ml_preds != deterministic_preds))
    agreement_rate = float(agreement_count / len(df_test))
    kappa = float(cohen_kappa_score(ml_preds, deterministic_preds))

    print(f"Total locked test certificates: {len(df_test)}")
    print(f"Deterministic Rule Engine Accuracy vs Ground Truth: {rule_vs_gt['accuracy']:.6f} (F1: {rule_vs_gt['macro_f1']:.6f})")
    print(f"Machine Learning Model Accuracy vs Ground Truth:     {ml_vs_gt['accuracy']:.6f} (F1: {ml_vs_gt['macro_f1']:.6f})")
    print(f"\nExact Agreement between ML and Deterministic Rules: {agreement_count}/{len(df_test)} ({agreement_rate*100:.4f}%)")
    print(f"Disagreements: {disagreement_count}")
    print(f"Cohen's Kappa (ML vs Rule Engine): {kappa:.6f}")

    return {
        "rule_vs_ground_truth": rule_vs_gt,
        "ml_vs_ground_truth": ml_vs_gt,
        "ml_vs_rule_engine": {
            "agreement_rate": agreement_rate,
            "agreement_count": agreement_count,
            "disagreement_count": disagreement_count,
            "cohens_kappa": kappa,
        }
    }


def main():
    print("=" * 70)
    print("PHASE 6: FEATURE ABLATION & DETERMINISTIC BASELINE COMPARISON")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    df_test = dataset_loader.extract_tabular_features(splits["test"], labels_map)

    import joblib
    champion_path = _ANALYZER_SRC / "certificate_analyzer" / "ml" / "artifacts" / "champion_model.joblib"
    champion_pipeline = joblib.load(champion_path)

    ablation_results = run_ablation(df_train, df_test)
    comparison_results = run_rule_baseline_comparison(df_test, champion_pipeline)

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase6_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "ablation": ablation_results,
            "baseline_comparison": comparison_results,
        }, f, indent=2)

    print(f"\nPhase 6 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()

