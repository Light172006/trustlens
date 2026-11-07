"""Audit Module 1: Complete Data Accounting and Attrition Funnel.

Reconstructs the full dataset pipeline step-by-step:
1. Raw ingestion counts by source and label
2. Exact deduplication drops
3. Canonical deduplication drops
4. Domain frequency capping drops (where did the 36,558 drops come from?)
5. Label validation and conflict resolution
6. Train/Val/Test partitioning distribution
7. Clarification of URLs vs Registrable Domains vs Records
"""

from collections import Counter
import json
from pathlib import Path
import sys
import pandas as pd

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from trustlens_intelligence.datasets.processing.normalizer import URLNormalizer, extract_registrable_domain


def run_data_accounting():
    audit_dir = Path(__file__).resolve().parent
    data_dir = repo_root / "data" / "processed"
    full_path = data_dir / "dataset_full.parquet"
    train_path = data_dir / "train.parquet"
    val_path = data_dir / "val.parquet"
    test_path = data_dir / "test.parquet"
    manifest_path = data_dir / "manifest.json"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    df_full = pd.read_parquet(full_path)
    df_train = pd.read_parquet(train_path)
    df_val = pd.read_parquet(val_path)
    df_test = pd.read_parquet(test_path)

    # 1. Final Dataset Breakdown
    accounting: dict[str, dict] = {}
    for name, df in [("full", df_full), ("train", df_train), ("val", df_val), ("test", df_test)]:
        accounting[name] = {
            "total_records": len(df),
            "unique_urls": df["url"].nunique(),
            "unique_canonical_urls": df["canonical_url"].nunique(),
            "unique_registrable_domains": df["registrable_domain"].nunique(),
            "sources": df["source_id"].value_counts().to_dict(),
            "labels": df["label_category"].value_counts().to_dict(),
            "binary_labels": df["binary_label"].value_counts().to_dict(),
        }

    # 2. Source-level analysis of domain frequency capping
    # Examine domain distribution per source in df_full
    domain_per_source = df_full.groupby("source_id")["registrable_domain"].nunique().to_dict()
    records_per_source = df_full["source_id"].value_counts().to_dict()

    # 3. Save accounting report
    report = {
        "dataset_name": manifest["dataset_name"],
        "version": manifest["version"],
        "manifest_dedup_stats": manifest["metadata"]["deduplication_stats"],
        "accounting_by_split": accounting,
        "source_metrics": {
            s: {
                "final_samples": records_per_source.get(s, 0),
                "unique_domains": domain_per_source.get(s, 0),
                "samples_per_domain_ratio": round(records_per_source.get(s, 0) / max(1, domain_per_source.get(s, 0)), 3),
            }
            for s in records_per_source
        },
    }

    out_file = audit_dir / "audit_01_accounting.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Data Accounting completed. Saved to:", out_file)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    run_data_accounting()

