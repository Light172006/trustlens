"""
TrustLens Web Security Analyzer - End-to-End Dataset Engineering Pipeline
Orchestrates normalization, deduplication, multi-label annotation, zero-leakage splitting,
canonical Parquet/CSV export, cryptographic manifest generation, and quality auditing.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import yaml

from annotate import annotate_records
from create_splits import create_zero_leakage_splits, save_splits
from deduplicate import deduplicate_records
from normalize import run_normalization
from validate import generate_quality_report, validate_labels, validate_schema, validate_splits, validate_uniqueness

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_pipeline")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def compute_sha256(filepath: Path) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def generate_dataset_manifest(
    processed_parquet: Path,
    processed_csv: Path,
    splits_dir: Path,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """Generates cryptographic SHA-256 manifest for all canonical dataset deliverables."""
    manifest_files = {}

    for p in [processed_parquet, processed_csv]:
        if p.exists():
            manifest_files[p.name] = {
                "relative_path": str(p.relative_to(BASE_DIR)).replace("\\", "/"),
                "size_bytes": p.stat().st_size,
                "sha256": compute_sha256(p),
            }

    for split_name in ["train.parquet", "validation.parquet", "test.parquet"]:
        p = splits_dir / split_name
        if p.exists():
            manifest_files[f"splits/{split_name}"] = {
                "relative_path": str(p.relative_to(BASE_DIR)).replace("\\", "/"),
                "size_bytes": p.stat().st_size,
                "sha256": compute_sha256(p),
            }

    synthetic_p = BASE_DIR / config["paths"]["synthetic_parquet"]
    if synthetic_p.exists():
        manifest_files["synthetic/lab_dataset.parquet"] = {
            "relative_path": str(synthetic_p.relative_to(BASE_DIR)).replace("\\", "/"),
            "size_bytes": synthetic_p.stat().st_size,
            "sha256": compute_sha256(synthetic_p),
        }

    manifest = {
        "manifest_version": "1.0.0",
        "dataset_name": config["project"]["name"],
        "dataset_version": config["project"]["version"],
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cryptographic_algorithm": "SHA-256",
        "files": manifest_files,
    }

    manifest_path = BASE_DIR / config["paths"]["manifest_json"]
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Generated cryptographic manifest at {manifest_path}")
    return manifest


def run_pipeline(config_path: Optional[str] = None, min_domains: int = 10000) -> None:
    config = load_config(config_path)
    logger.info("=== Starting TrustLens Web Security Dataset Pipeline ===")

    # Step 1: Normalization
    logger.info("Step 1: Running normalization & Public Suffix List parsing...")
    normalized_records = run_normalization(config_path)
    logger.info(f"Normalized records: {len(normalized_records)}")

    # Step 2: Deduplication
    logger.info("Step 2: Enforcing strict registrable-domain level uniqueness...")
    deduped_records = deduplicate_records(normalized_records)
    logger.info(f"Deduplicated unique registrable domains: {len(deduped_records)}")

    if len(deduped_records) < min_domains:
        raise ValueError(
            f"Insufficient unique domains: {len(deduped_records)} < minimum requirement of {min_domains}!"
        )

    # Step 3: Multi-label Annotation & Posture Scoring
    logger.info("Step 3: Applying security findings, taxonomy rules, and posture scoring...")
    annotated_records = annotate_records(deduped_records)

    # Convert to canonical DataFrame
    df = pd.DataFrame(annotated_records)
    logger.info(f"Canonical DataFrame created with shape: {df.shape}")

    # Step 4: Export Canonical Processed Datasets
    processed_dir = BASE_DIR / config["paths"]["processed_dir"]
    processed_dir.mkdir(parents=True, exist_ok=True)

    parquet_path = BASE_DIR / config["paths"]["processed_parquet"]
    csv_path = BASE_DIR / config["paths"]["processed_csv"]

    logger.info(f"Step 4: Writing canonical Parquet dataset to {parquet_path}...")
    df.to_parquet(parquet_path, index=False, engine="pyarrow")

    logger.info(f"Writing CSV export to {csv_path}...")
    # For CSV export, serialize complex columns cleanly
    df_csv = df.copy()
    if "dns_ipv4_addresses" in df_csv.columns:
        df_csv["dns_ipv4_addresses"] = df_csv["dns_ipv4_addresses"].apply(lambda x: ";".join(x) if isinstance(x, list) else str(x))
    if "tls_cert_sans" in df_csv.columns:
        df_csv["tls_cert_sans"] = df_csv["tls_cert_sans"].apply(lambda x: ";".join(x) if isinstance(x, list) else str(x))
    if "finding_ids" in df_csv.columns:
        df_csv["finding_ids"] = df_csv["finding_ids"].apply(lambda x: ";".join(x) if isinstance(x, list) else str(x))
    df_csv.to_csv(csv_path, index=False, encoding="utf-8")

    # Step 5: Zero-Leakage Splits Generation
    logger.info("Step 5: Generating zero-leakage evaluation splits (70/15/15)...")
    train_df, val_df, test_df = create_zero_leakage_splits(
        df,
        train_ratio=config["splits"]["train_ratio"],
        val_ratio=config["splits"]["validation_ratio"],
        test_ratio=config["splits"]["test_ratio"],
        random_seed=config["splits"]["random_seed"],
    )
    save_splits(train_df, val_df, test_df, config)

    # Step 6: Quality Auditing & Statistical Reporting
    logger.info("Step 6: Executing automated data quality audits and generating quality report...")
    quality_report_path = BASE_DIR / config["paths"]["quality_report_json"]
    quality_report = generate_quality_report(df, train_df, val_df, test_df, quality_report_path)

    # Step 7: Cryptographic Manifest
    logger.info("Step 7: Generating SHA-256 cryptographic manifest...")
    splits_dir = BASE_DIR / config["paths"]["splits_dir"]
    generate_dataset_manifest(parquet_path, csv_path, splits_dir, config)

    logger.info("=== TrustLens Web Security Dataset Pipeline Successfully Completed! ===")
    logger.info(f"  Total Unique Registrable Domains: {len(df)}")
    logger.info(f"  Parquet Dataset: {parquet_path} ({parquet_path.stat().st_size:,} bytes)")
    logger.info(f"  CSV Dataset:     {csv_path} ({csv_path.stat().st_size:,} bytes)")
    logger.info(f"  Train Split:     {len(train_df):,} rows")
    logger.info(f"  Val Split:       {len(val_df):,} rows")
    logger.info(f"  Test Split:      {len(test_df):,} rows")


def main():
    parser = argparse.ArgumentParser(description="TrustLens Web Security Dataset Pipeline")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    parser.add_argument("--min-domains", type=int, default=10000, help="Minimum unique registrable domains")
    args = parser.parse_args()

    run_pipeline(config_path=args.config, min_domains=args.min_domains)


if __name__ == "__main__":
    main()

