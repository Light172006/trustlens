"""Phase 11 Audit: Candidate vs Champion Comparative Benchmark.

Benchmarks Logistic Regression, Random Forest, and HistGradientBoosting across:
1. Macro F1, Accuracy, Brier score on locked test set.
2. Single-sample and batch inference latency.
3. Memory and serialized artifact footprint.
4. Step-function threshold handling (e.g. 5-year certificate edge case).
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time

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
from certificate_analyzer.ml.models import CertificateModelFactory
from certificate_analyzer.ml.preprocessing import NUMERIC_FEATURES, CATEGORICAL_FEATURES


def main():
    print("=" * 70)
    print("PHASE 11: CANDIDATE VS CHAMPION COMPARATIVE BENCHMARK")
    print("=" * 70)

    dataset_loader = CertificateMLDataset()
    splits = dataset_loader.load_split_records(split_type="spki_disjoint")
    labels_map = dataset_loader.get_labels_map()

    df_train = dataset_loader.extract_tabular_features(splits["train"], labels_map)
    df_test = dataset_loader.extract_tabular_features(splits["test"], labels_map)

    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X_train, y_train = df_train[feature_cols], df_train["target"].to_numpy()
    X_test, y_test = df_test[feature_cols], df_test["target"].to_numpy()

    candidates = CertificateModelFactory.get_candidate_models()
    benchmark_results = {}

    single_sample = X_test.iloc[0:1]

    print(f"{'Architecture':<24} | {'Test Acc':<9} | {'Test F1':<9} | {'Brier':<10} | {'1-Sample Lat':<14} | {'Batch Lat':<10} | {'Artifact Size'}")
    print("-" * 105)

    candidate_dir = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "candidate_artifacts"
    candidate_dir.mkdir(parents=True, exist_ok=True)

    for name, pipeline in candidates.items():
        # Fit model
        t0 = time.perf_counter()
        pipeline.fit(X_train, y_train)
        fit_time = time.perf_counter() - t0

        # Predict test
        test_preds = pipeline.predict(X_test)
        test_probs = pipeline.predict_proba(X_test)[:, 1]
        m = CertificateMLEvaluator.evaluate(y_test, test_preds, test_probs)

        # Measure 1-sample latency (100 runs)
        latencies = []
        for _ in range(100):
            t_start = time.perf_counter()
            _ = pipeline.predict_proba(single_sample)
            latencies.append((time.perf_counter() - t_start) * 1e6)  # microseconds
        mean_single_lat_us = float(np.mean(latencies))

        # Measure batch latency (full 3,854 test samples)
        t_batch_start = time.perf_counter()
        _ = pipeline.predict_proba(X_test)
        batch_lat_ms = float((time.perf_counter() - t_batch_start) * 1e3)

        # Save to candidate dir to measure size
        art_path = candidate_dir / f"candidate_{name}.joblib"
        joblib.dump(pipeline, art_path)
        art_size_kb = float(art_path.stat().st_size / 1024.0)

        # Check the 5-year false positive sample from Phase 1
        fp_sample = df_test[df_test["validity_duration_days"] > 1800.0]
        if not fp_sample.empty:
            fp_pred = int(pipeline.predict(fp_sample[feature_cols])[0])
            fp_prob = float(pipeline.predict_proba(fp_sample[feature_cols])[0, 1])
        else:
            fp_pred, fp_prob = -1, -1.0

        rec = {
            "name": name,
            "fit_time_seconds": fit_time,
            "metrics": m,
            "single_sample_latency_microseconds": mean_single_lat_us,
            "batch_latency_milliseconds": batch_lat_ms,
            "artifact_size_kb": art_size_kb,
            "fp_sample_prediction": fp_pred,
            "fp_sample_probability": fp_prob,
        }
        benchmark_results[name] = rec

        print(f"{name:<24} | {m['accuracy']:<9.4f} | {m['macro_f1']:<9.4f} | {m.get('brier_score', 0):<10.6e} | {mean_single_lat_us:>8.2f} us    | {batch_lat_ms:>6.2f} ms   | {art_size_kb:>8.1f} KB")

    out_file = _ROOT / "intelligence" / "certificate_analyzer" / "audit" / "phase11_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    print(f"\nPhase 11 Audit Complete. Results saved to {out_file}")


if __name__ == "__main__":
    main()
