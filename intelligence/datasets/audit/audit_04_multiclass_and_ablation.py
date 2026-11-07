"""Audit Module 4: Multi-Class Evaluation and 7-Way Feature Ablation Suite.

1. Evaluates binary vs multi-class (Legitimate, Phishing, Malware) performance.
2. Executes the 7 feature ablation configurations specified in Section 9.
"""

import json
from pathlib import Path
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES


def run_multiclass_and_ablation():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    df_train = pd.read_parquet(data_dir / "train.parquet")
    df_test = pd.read_parquet(data_dir / "test.parquet")

    # =========================================================================
    # PART 1: Multi-Class Evaluation (Legitimate vs Phishing vs Malware)
    # =========================================================================
    print("Running Part 1: Multi-Class 3-Way Classification...")
    class_map = {"legitimate": 0, "phishing": 1, "malware": 2}
    class_names = ["legitimate", "phishing", "malware"]

    y_train_3 = df_train["label_category"].map(class_map)
    y_test_3 = df_test["label_category"].map(class_map)

    feature_cols = list(ML_INTRINSIC_FEATURE_NAMES)
    X_train = df_train[feature_cols].copy()
    X_test = df_test[feature_cols].copy()

    clf_3 = HistGradientBoostingClassifier(max_iter=150, random_state=42, class_weight="balanced")
    clf_3.fit(X_train, y_train_3)

    y_pred_3 = clf_3.predict(X_test)
    y_proba_3 = clf_3.predict_proba(X_test)

    rep_3 = classification_report(y_test_3, y_pred_3, target_names=class_names, output_dict=True)
    cm_3 = confusion_matrix(y_test_3, y_pred_3).tolist()

    # One-vs-rest ROC-AUC
    try:
        ovr_roc_auc = float(roc_auc_score(y_test_3, y_proba_3, multi_class="ovr", average="macro"))
    except Exception:
        ovr_roc_auc = None

    # Performance of the existing binary model on individual classes
    # Check how binary threat predictions break down across phishing vs malware
    import joblib
    artifact = joblib.load(repo_root / "trustlens_intelligence" / "evaluation" / "artifacts" / "baseline_classifier.joblib")
    bin_model = artifact["model"]
    bin_pred = bin_model.predict(X_test)

    threat_mask = df_test["binary_label"] == 1
    phish_mask = df_test["label_category"] == "phishing"
    malw_mask = df_test["label_category"] == "malware"

    bin_on_phish_recall = float((bin_pred[phish_mask] == 1).mean())
    bin_on_malw_recall = float((bin_pred[malw_mask] == 1).mean())

    multiclass_results = {
        "task": "3-class (legitimate, phishing, malware)",
        "confusion_matrix": cm_3,
        "classification_report": rep_3,
        "macro_f1": rep_3["macro avg"]["f1-score"],
        "weighted_f1": rep_3["weighted avg"]["f1-score"],
        "ovr_roc_auc": ovr_roc_auc,
        "existing_binary_model_breakdown": {
            "recall_on_phishing": bin_on_phish_recall,
            "recall_on_malware": bin_on_malw_recall,
            "phishing_sample_count": int(phish_mask.sum()),
            "malware_sample_count": int(malw_mask.sum()),
        },
    }

    # =========================================================================
    # PART 2: 7-Way Feature Ablation Suite
    # =========================================================================
    print("Running Part 2: 7-Way Feature Ablation...")
    lexical_features = [
        "url_length", "host_length", "path_length", "query_length",
        "url_entropy", "host_entropy", "digit_count", "special_char_count",
        "suspicious_keyword_count",
    ]
    structural_features = [
        "subdomain_count", "is_ip_host", "has_userinfo",
        "is_punycode", "has_homoglyphs", "has_non_standard_port",
    ]
    domain_features = ["domain_age_days"]
    http_tls_features = [
        "is_https", "redirect_count", "has_cross_domain_redirect",
        "http_to_https_redirect", "has_hsts", "has_csp",
        "has_x_content_type_options", "has_referrer_policy",
        "has_permissions_policy", "insecure_cookie_count",
        "missing_httponly_cookie_count", "missing_samesite_cookie_count",
        "tls_valid", "cert_chain_valid", "cert_hostname_match",
        "cert_is_expired", "cert_days_until_expiry", "is_legacy_tls",
    ]

    ablation_configs = {
        "1_all_34_intrinsic_features": feature_cols,
        "2_url_lexical_only": lexical_features,
        "3_url_structural_only": structural_features,
        "4_domain_features_only": domain_features,
        "5_http_and_tls_only": http_tls_features,
        "6_all_without_domain_age": [c for c in feature_cols if c != "domain_age_days"],
        "7_without_missingness_sentinels": [
            c for c in feature_cols
            if not ("cert" in c or "tls" in c or "domain_age" in c)
        ],
    }

    y_train_bin = df_train["binary_label"]
    y_test_bin = df_test["binary_label"]

    ablation_results = {}
    for name, cols in ablation_configs.items():
        print(f"  Training ablation: {name} ({len(cols)} features)...")
        clf_ab = HistGradientBoostingClassifier(max_iter=100, random_state=42, class_weight="balanced")
        clf_ab.fit(df_train[cols], y_train_bin)
        preds = clf_ab.predict(df_test[cols])
        probas = clf_ab.predict_proba(df_test[cols])[:, 1]

        p, r, f1, _ = precision_recall_fscore_support(y_test_bin, preds, average="binary", zero_division=0)
        acc = float((preds == y_test_bin).mean())
        roc = float(roc_auc_score(y_test_bin, probas))
        cm = confusion_matrix(y_test_bin, preds)
        fpr = float(cm[0, 1] / (cm[0, 0] + cm[0, 1]))

        ablation_results[name] = {
            "num_features": len(cols),
            "features": cols,
            "accuracy": acc,
            "precision": float(p),
            "recall": float(r),
            "f1": float(f1),
            "roc_auc": roc,
            "false_positive_rate": fpr,
        }

    results = {
        "multiclass_evaluation": multiclass_results,
        "ablation_experiments": ablation_results,
    }

    out_file = audit_dir / "audit_04_multiclass_ablation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n=== MULTI-CLASS & ABLATION SUMMARY ===")
    print("Multi-class F1 per category:")
    for cat in class_names:
        print(f"  - {cat.capitalize()}: F1={rep_3[cat]['f1-score']:.4f}, Recall={rep_3[cat]['recall']:.4f}")

    print("\nAblation Performance Across Configurations:")
    for name, m in ablation_results.items():
        print(f"  - {name} ({m['num_features']} feats): F1={m['f1']:.4f}, Acc={m['accuracy']:.4f}, FPR={m['false_positive_rate']:.4f}")


if __name__ == "__main__":
    run_multiclass_and_ablation()
