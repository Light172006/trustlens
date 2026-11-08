"""Phase 7 Audit: Isolation Forest Anomaly Detector Stress Testing.

Evaluates the unsupervised Isolation Forest against:
1. Legitimate but rare Web PKI profiles (high SANs, rare curves, short validity).
2. False alarm rates across contamination thresholds (1%, 5%, 10%).
3. Anomaly score distribution and decision boundaries.
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
import pandas as pd

from certificate_analyzer.ml.dataset import CertificateMLDataset
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def test_rare_profiles(anomaly_pipeline):
    print("\n--- 1. Stress Testing on Legitimate Rare Web PKI Profiles ---")

    # Define synthetic yet fully RFC-compliant rare profiles
    rare_profiles = [
        {
            "name": "Cloudflare High-SAN CDN (SAN=100)",
            "key_size_bits": 256.0,
            "validity_duration_days": 90.0,
            "san_count": 100,
            "is_wildcard": 1,
            "has_scts": 1,
            "sct_count": 3,
            "extension_count": 9,
            "key_usage_count": 1,
            "extended_key_usage_count": 2,
            "is_ca": 0,
            "is_self_signed": 0,
            "subject_dn_length": 60,
            "key_algorithm": "ECDSA",
            "ec_curve": "secp256r1",
            "signature_algorithm": "ecdsa-with-SHA256",
        },
        {
            "name": "NIST P-384 High-Security Government (secp384r1)",
            "key_size_bits": 384.0,
            "validity_duration_days": 365.0,
            "san_count": 2,
            "is_wildcard": 0,
            "has_scts": 1,
            "sct_count": 2,
            "extension_count": 8,
            "key_usage_count": 2,
            "extended_key_usage_count": 1,
            "is_ca": 0,
            "is_self_signed": 0,
            "subject_dn_length": 120,
            "key_algorithm": "ECDSA",
            "ec_curve": "secp384r1",
            "signature_algorithm": "ecdsa-with-SHA384",
        },
        {
            "name": "Ultra-Short Lifespan (6-day automated leaf)",
            "key_size_bits": 2048.0,
            "validity_duration_days": 6.0,
            "san_count": 1,
            "is_wildcard": 0,
            "has_scts": 1,
            "sct_count": 2,
            "extension_count": 7,
            "key_usage_count": 2,
            "extended_key_usage_count": 1,
            "is_ca": 0,
            "is_self_signed": 0,
            "subject_dn_length": 45,
            "key_algorithm": "RSA",
            "ec_curve": "none",
            "signature_algorithm": "sha256WithRSAEncryption",
        },
        {
            "name": "Enterprise Multi-Purpose EKU (serverAuth+clientAuth+emailProtection)",
            "key_size_bits": 4096.0,
            "validity_duration_days": 397.0,
            "san_count": 5,
            "is_wildcard": 0,
            "has_scts": 1,
            "sct_count": 2,
            "extension_count": 10,
            "key_usage_count": 3,
            "extended_key_usage_count": 3,
            "is_ca": 0,
            "is_self_signed": 0,
            "subject_dn_length": 180,
            "key_algorithm": "RSA",
            "ec_curve": "none",
            "signature_algorithm": "sha256WithRSAEncryption",
        },
        {
            "name": "Typical Standard Let's Encrypt DV (Baseline Control)",
            "key_size_bits": 256.0,
            "validity_duration_days": 89.9,
            "san_count": 2,
            "is_wildcard": 0,
            "has_scts": 1,
            "sct_count": 2,
            "extension_count": 8,
            "key_usage_count": 1,
            "extended_key_usage_count": 2,
            "is_ca": 0,
            "is_self_signed": 0,
            "subject_dn_length": 35,
            "key_algorithm": "ECDSA",
            "ec_curve": "secp256r1",
            "signature_algorithm": "ecdsa-with-SHA256",
        },
    ]

    df_rare = pd.DataFrame(rare_profiles)
    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_rare = df_rare[feature_cols]

    preds = anomaly_pipeline.predict(X_rare)  # -1 = anomaly, 1 = normal
    scores = anomaly_pipeline.decision_function(X_rare)

    results = []
    print(f"{'Profile':<42} | {'Verdict':<10} | {'Score':<8} | False Alarm?")
    print("-" * 75)
    for i, p in enumerate(rare_profiles):
        is_ano = bool(preds[i] == -1)
        score = float(scores[i])
        verdict = "ANOMALY" if is_ano else "NORMAL"
        is_false_alarm = bool(is_ano)  # All test cases are 100% legitimate Web PKI profiles
        print(f"{p['name']:<42} | {verdict:<10} | {score:<+8.4f} | {'YES (False Alarm)' if is_false_alarm else 'NO (Correct)'}")
        results.append({
            "name": p["name"],
            "verdict": verdict,
            "is_anomaly": is_ano,
            "decision_score": score,
            "is_false_alarm": is_false_alarm,
        })

    return results


def test_contamination_sensitivity(df_train_compliant, df_test_compliant):
    print("\n--- 2. Sensitivity Across Contamination Levels (1%, 5%, 10%) ---")
    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_train = df_train_compliant[feature_cols]
    X_test = df_test_compliant[feature_cols]

    contaminations = [0.01, 0.05, 0.10]
    sensitivity_results = {}

    for cont in contaminations:
        pipeline = CertificateModelFactory.get_anomaly_detector(contamination=cont)
        pipeline.fit(X_train)

        test_preds = pipeline.predict(X_test)
        test_scores = pipeline.decision_function(X_test)

        # All test samples here are compliant Web PKI certificates
        n_anomalies = int(np.sum(test_preds == -1))
        rate = float(n_anomalies / len(test_preds))

        sensitivity_results[str(cont)] = {
            "contamination_parameter": cont,
            "test_samples": len(test_preds),
            "flagged_as_anomaly": n_anomalies,
            "empirical_false_alarm_rate": rate,
            "score_mean": float(np.mean(test_scores)),
            "score_std": float(np.std(test_scores)),
            "score_min": float(np.min(test_scores)),
            "score_max": float(np.max(test_scores)),
        }

        print(f"Contamination: {cont*100:>4.1f}% | Compliant Test Samples Flagged: {n_anomalies}/{len(test_preds)} ({rate*100:.2f}%) | Score Mean: {np.mean(test_scores):+.4f}")

    return sensitivity_results


def main():
    print("=" * 70)
    print("PHASE 7: ANOMALY DETECTOR (ISOLATION FOREST) AUDIT & STRESS TESTING")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    df_test = dataset_loader.extract_tabular_features(splits["test"], labels_map)

    # Compliant sets
    df_tr_comp = df_train[df_train["target"] == 1]
    df_te_comp = df_test[df_test["target"] == 1]

    anomaly_path = _ANALYZER_SRC / "certificate_analyzer" / "ml" / "artifacts" / "anomaly_detector.joblib"
    anomaly_pipeline = joblib.load(anomaly_path)

    rare_profile_results = test_rare_profiles(anomaly_pipeline)
    sensitivity_results = test_contamination_sensitivity(df_tr_comp, df_te_comp)

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase7_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "rare_profiles": rare_profile_results,
            "sensitivity": sensitivity_results,
        }, f, indent=2)

    print(f"\nPhase 7 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
