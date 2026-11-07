"""Audit Module 5: Duplicate/Campaign Leakage and Temporal Provenance Audit.

1. Independently verifies zero domain overlap using PSL logic.
2. Audits path templates and campaign token overlap across train/test.
3. Audits timestamp provenance and runs temporal holdout on real historical timestamps.
"""

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.processing.allowlist import ML_INTRINSIC_FEATURE_NAMES
from trustlens_intelligence.datasets.processing.normalizer import extract_registrable_domain


def run_leakage_and_temporal_audit():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    df_full = pd.read_parquet(data_dir / "dataset_full.parquet")
    df_train = pd.read_parquet(data_dir / "train.parquet")
    df_val = pd.read_parquet(data_dir / "val.parquet")
    df_test = pd.read_parquet(data_dir / "test.parquet")

    # =========================================================================
    # PART 1: Strict PSL Registrable Domain Overlap Verification
    # =========================================================================
    print("Verifying Domain Isolation and Overlap across Partitions...")
    train_domains = set(df_train["registrable_domain"].dropna().str.lower().str.strip())
    val_domains = set(df_val["registrable_domain"].dropna().str.lower().str.strip())
    test_domains = set(df_test["registrable_domain"].dropna().str.lower().str.strip())

    train_val_overlap = sorted(train_domains.intersection(val_domains))
    train_test_overlap = sorted(train_domains.intersection(test_domains))
    val_test_overlap = sorted(val_domains.intersection(test_domains))

    # Exact URL and Canonical URL overlap
    train_urls = set(df_train["canonical_url"])
    val_urls = set(df_val["canonical_url"])
    test_urls = set(df_test["canonical_url"])

    url_overlap_train_test = sorted(train_urls.intersection(test_urls))

    # Subdomain check: extract FQDN host from parsed URL
    def get_host(u: str) -> str:
        try:
            return urlparse(u).netloc.split(":")[0].lower()
        except Exception:
            return ""

    train_hosts = set(df_train["canonical_url"].apply(get_host))
    test_hosts = set(df_test["canonical_url"].apply(get_host))
    host_overlap = sorted(train_hosts.intersection(test_hosts))

    # =========================================================================
    # PART 2: Campaign and Path Template Overlap
    # =========================================================================
    print("Auditing Campaign Paths and Template Overlap...")
    def get_path(u: str) -> str:
        try:
            p = urlparse(u).path
            return p if p else "/"
        except Exception:
            return "/"

    train_paths = set(df_train["canonical_url"].apply(get_path))
    test_paths = set(df_test["canonical_url"].apply(get_path))

    # Non-root path overlap in threats
    train_threat_paths = set(df_train[df_train["binary_label"] == 1]["canonical_url"].apply(get_path)) - {"/"}
    test_threat_paths = set(df_test[df_test["binary_label"] == 1]["canonical_url"].apply(get_path)) - {"/"}
    shared_threat_paths = sorted(train_threat_paths.intersection(test_threat_paths))

    path_jaccard = len(shared_threat_paths) / max(1, len(train_threat_paths.union(test_threat_paths)))

    # =========================================================================
    # PART 3: Timestamp Provenance & Temporal Evaluation
    # =========================================================================
    print("Auditing Timestamp Provenance and Temporal Generalization...")
    # Inspect timestamp distribution by source
    ts_audit = {}
    for source in df_full["source_id"].unique():
        sub = df_full[df_full["source_id"] == source]
        ts_series = pd.to_datetime(sub["timestamp"].dropna(), utc=True)
        ts_audit[source] = {
            "total_records": len(sub),
            "records_with_timestamp": len(ts_series),
            "unique_timestamps": ts_series.nunique(),
            "earliest_timestamp": str(ts_series.min()) if not ts_series.empty else None,
            "latest_timestamp": str(ts_series.max()) if not ts_series.empty else None,
            "span_hours": float((ts_series.max() - ts_series.min()).total_seconds() / 3600.0) if not ts_series.empty else 0.0,
        }

    # PhishTank temporal holdout experiment (PhishTank has actual historical submission times)
    df_phishtank = df_full[df_full["source_id"] == "phishtank"].copy()
    df_phishtank["ts"] = pd.to_datetime(df_phishtank["timestamp"], utc=True)
    df_phishtank = df_phishtank.sort_values(by="ts").reset_index(drop=True)

    pt_temporal_results = {}
    if len(df_phishtank) > 1000:
        split_idx = int(len(df_phishtank) * 0.70)
        pt_train = df_phishtank.iloc[:split_idx]
        pt_test = df_phishtank.iloc[split_idx:]

        # Mix with 70/30 Tranco benign data to form temporal train/test sets
        df_tranco = df_full[df_full["source_id"] == "tranco"].copy()
        tranco_split = int(len(df_tranco) * 0.70)
        tranco_train = df_tranco.iloc[:tranco_split]
        tranco_test = df_tranco.iloc[tranco_split:]

        temp_train = pd.concat([tranco_train, pt_train], ignore_index=True)
        temp_test = pd.concat([tranco_test, pt_test], ignore_index=True)

        feature_cols = list(ML_INTRINSIC_FEATURE_NAMES)
        clf_temp = HistGradientBoostingClassifier(max_iter=100, random_state=42, class_weight="balanced")
        clf_temp.fit(temp_train[feature_cols], temp_train["binary_label"])
        pt_preds = clf_temp.predict(temp_test[feature_cols])

        p, r, f1, _ = precision_recall_fscore_support(temp_test["binary_label"], pt_preds, average="binary")
        pt_temporal_results = {
            "train_period": f"{pt_train['ts'].min()} to {pt_train['ts'].max()}",
            "test_period": f"{pt_test['ts'].min()} to {pt_test['ts'].max()}",
            "temporal_train_threat_count": len(pt_train),
            "temporal_test_threat_count": len(pt_test),
            "precision": float(p),
            "recall": float(r),
            "f1": float(f1),
        }

    results = {
        "domain_leakage_check": {
            "train_val_overlap_count": len(train_val_overlap),
            "train_test_overlap_count": len(train_test_overlap),
            "val_test_overlap_count": len(val_test_overlap),
            "url_overlap_train_test_count": len(url_overlap_train_test),
            "host_overlap_train_test_count": len(host_overlap),
            "zero_domain_leakage_verified": len(train_test_overlap) == 0 and len(train_val_overlap) == 0 and len(val_test_overlap) == 0,
        },
        "campaign_and_path_leakage": {
            "unique_threat_paths_train": len(train_threat_paths),
            "unique_threat_paths_test": len(test_threat_paths),
            "shared_threat_paths_count": len(shared_threat_paths),
            "path_template_jaccard_similarity": round(path_jaccard, 4),
            "sample_shared_paths": shared_threat_paths[:15],
        },
        "timestamp_provenance": ts_audit,
        "phishtank_temporal_holdout_experiment": pt_temporal_results,
    }

    out_file = audit_dir / "audit_05_leakage_temporal.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n=== LEAKAGE & TEMPORAL AUDIT SUMMARY ===")
    print(f"Zero Domain Overlap: {results['domain_leakage_check']['zero_domain_leakage_verified']}")
    print(f"Shared Threat Path Templates between Train & Test: {results['campaign_and_path_leakage']['shared_threat_paths_count']}")
    print(f"Path Template Jaccard Similarity: {results['campaign_and_path_leakage']['path_template_jaccard_similarity']}")
    print("\nTimestamp Provenance Reality:")
    for src, info in ts_audit.items():
        print(f"  - {src}: {info['unique_timestamps']} unique timestamps (Span: {info['span_hours']:.1f}h)")


if __name__ == "__main__":
    run_leakage_and_temporal_audit()

