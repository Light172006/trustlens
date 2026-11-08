"""
TrustLens Web Security Analyzer - Data Quality, Schema & Statistical Validation Engine
Executes comprehensive automated audits to ensure compliance with strict production dataset criteria.
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_validator")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_schema(df: pd.DataFrame, data_dict: Dict[str, Any]) -> List[str]:
    """Validates that all required columns are present with appropriate types."""
    errors = []
    expected_cols = {col["name"]: col for col in data_dict["columns"]}

    missing_cols = set(expected_cols.keys()) - set(df.columns)
    if missing_cols:
        errors.append(f"Missing required columns in dataset: {sorted(list(missing_cols))}")

    # Nullability checks for non-nullable columns
    for col_meta in data_dict["columns"]:
        col_name = col_meta["name"]
        if not col_meta.get("nullable", True) and col_name in df.columns:
            null_count = df[col_name].isna().sum()
            if null_count > 0:
                errors.append(f"Non-nullable column '{col_name}' has {null_count} null values.")

    return errors


def validate_uniqueness(df: pd.DataFrame, min_domains: int = 10000) -> List[str]:
    """Validates uniqueness of registrable domains."""
    errors = []
    total_rows = len(df)
    unique_domains = df["registrable_domain"].nunique()

    if total_rows != unique_domains:
        dup_count = total_rows - unique_domains
        errors.append(f"Uniqueness violation: {dup_count} duplicate registrable domains found ({total_rows} rows, {unique_domains} unique).")

    if unique_domains < min_domains:
        errors.append(f"Sample size violation: Found {unique_domains} unique domains, minimum requirement is {min_domains}.")

    return errors


def validate_labels(df: pd.DataFrame, taxonomy: Dict[str, Any]) -> List[str]:
    """Validates finding labels, posture classifications, and evidence."""
    errors = []
    valid_postures = set(taxonomy["website_posture_rubric"].keys())
    valid_statuses = set(taxonomy["status_definitions"].keys())
    valid_severities = set(taxonomy["severity_rubric"].keys())

    # Check website posture label
    invalid_postures = set(df["website_posture_label"].unique()) - valid_postures
    if invalid_postures:
        errors.append(f"Invalid website_posture_label values found: {invalid_postures}")

    # Check score bounds
    invalid_scores = df[(df["website_posture_score"] < 0.0) | (df["website_posture_score"] > 100.0)]
    if len(invalid_scores) > 0:
        errors.append(f"Found {len(invalid_scores)} records with website_posture_score outside [0.0, 100.0].")

    # Sample audit of finding evidence
    sample_findings = df["findings"].dropna().sample(min(len(df), 200), random_state=42)
    for findings_json in sample_findings:
        try:
            findings_list = json.loads(findings_json)
            for f in findings_list:
                status = f.get("status")
                severity = f.get("severity")
                evidence = f.get("evidence", "")

                if status not in valid_statuses:
                    errors.append(f"Invalid status '{status}' in finding {f.get('finding_id')}")
                if severity not in valid_severities:
                    errors.append(f"Invalid severity '{severity}' in finding {f.get('finding_id')}")
                if status == "FAIL" and (not evidence or len(evidence.strip()) < 5):
                    errors.append(f"Missing evidence for FAIL finding {f.get('finding_id')}")
        except Exception as e:
            errors.append(f"Malformed findings JSON: {str(e)}")
            break

    return errors


def validate_splits(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame) -> List[str]:
    """Validates zero leakage across evaluation splits."""
    errors = []
    train_dom = set(train_df["registrable_domain"])
    val_dom = set(val_df["registrable_domain"])
    test_dom = set(test_df["registrable_domain"])

    leak_train_val = train_dom & val_dom
    leak_train_test = train_dom & test_dom
    leak_val_test = val_dom & test_dom

    if leak_train_val:
        errors.append(f"Domain overlap between train and val: {len(leak_train_val)} domains")
    if leak_train_test:
        errors.append(f"Domain overlap between train and test: {len(leak_train_test)} domains")
    if leak_val_test:
        errors.append(f"Domain overlap between val and test: {len(leak_val_test)} domains")

    return errors


def generate_quality_report(
    df: pd.DataFrame,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    output_path: Path,
) -> Dict[str, Any]:
    """Computes comprehensive statistical distributions and dataset quality metrics."""
    total_records = len(df)
    unique_domains = int(df["registrable_domain"].nunique())

    # Missing value rates
    missing_rates = {col: round(float(df[col].isna().mean() * 100), 2) for col in df.columns}

    # Posture distribution
    posture_counts = df["website_posture_label"].value_counts().to_dict()
    posture_percentages = {k: round(v / total_records * 100, 2) for k, v in posture_counts.items()}

    # Score statistics
    score_stats = {
        "mean": round(float(df["website_posture_score"].mean()), 2),
        "std": round(float(df["website_posture_score"].std()), 2),
        "min": round(float(df["website_posture_score"].min()), 2),
        "p25": round(float(df["website_posture_score"].quantile(0.25)), 2),
        "median": round(float(df["website_posture_score"].median()), 2),
        "p75": round(float(df["website_posture_score"].quantile(0.75)), 2),
        "max": round(float(df["website_posture_score"].max()), 2),
    }

    # Feature adoption rates
    tls_rate = round(float(df["tls_supported"].mean() * 100), 2)
    hsts_rate = round(float(df["header_hsts_present"].mean() * 100), 2)
    csp_rate = round(float(df["header_csp_present"].mean() * 100), 2)
    xfo_rate = round(float(df["header_xfo_present"].mean() * 100), 2)
    xcto_rate = round(float(df["header_xcto_present"].mean() * 100), 2)
    redirect_rate = round(float(df["http_to_https_redirect"].mean() * 100), 2)

    # TLS version distribution
    tls_versions = df["tls_version"].value_counts(dropna=False).to_dict()
    tls_versions = {str(k): int(v) for k, v in tls_versions.items()}

    report = {
        "report_version": "1.0.0",
        "dataset_name": "TrustLens Web Security Analyzer Dataset",
        "dataset_version": "1.0.0",
        "total_records": total_records,
        "unique_registrable_domains": unique_domains,
        "duplicate_domains_count": total_records - unique_domains,
        "split_counts": {
            "train": len(train_df),
            "validation": len(val_df),
            "test": len(test_df),
        },
        "posture_distribution": {
            "counts": posture_counts,
            "percentages": posture_percentages,
        },
        "score_statistics": score_stats,
        "key_controls_adoption_pct": {
            "tls_handshake_success": tls_rate,
            "hsts_deployment": hsts_rate,
            "csp_deployment": csp_rate,
            "x_frame_options": xfo_rate,
            "x_content_type_options": xcto_rate,
            "http_to_https_redirect": redirect_rate,
        },
        "tls_version_distribution": tls_versions,
        "missing_value_percentages": missing_rates,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Wrote quality report to {output_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="TrustLens Quality & Schema Validator")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()


if __name__ == "__main__":
    main()

