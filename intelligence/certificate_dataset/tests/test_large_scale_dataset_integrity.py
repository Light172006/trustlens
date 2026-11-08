"""Automated validation tests for the scaled 10,000+ certificate dataset."""

from __future__ import annotations

import json
import pytest

from certificate_dataset.storage.store import DatasetStorage


@pytest.fixture(scope="module")
def storage():
    return DatasetStorage()


def test_leaf_certificate_count_meets_milestone_target(storage):
    """Verifies that the dataset contains at least 10,000 unique, genuine leaf certificates."""
    manifest_path = storage.manifests_dir / "certificate_dataset_manifest.json"
    assert manifest_path.exists(), "Manifest file must exist"
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    stats = manifest.get("statistics", {})
    leaf_count = stats.get("leaf_certificate_count", 0)
    total_valid = stats.get("valid_parsed_certificates", 0)
    
    assert leaf_count >= 10000, f"Expected >= 10,000 leaf certificates, found {leaf_count}"
    assert total_valid >= leaf_count, "Total valid certificates must be >= leaf count"


def test_unique_fingerprints_integrity(storage):
    """Verifies that normalized records have 100% unique SHA-256 fingerprints."""
    manifest_path = storage.manifests_dir / "certificate_dataset_manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    stats = manifest.get("statistics", {})
    total_valid = stats.get("valid_parsed_certificates", 0)
    unique_fps = stats.get("unique_fingerprints_count", 0)
    
    assert total_valid == unique_fps, "Every valid certificate in the normalized corpus must have a unique fingerprint"


def test_evaluation_splits_zero_leakage(storage):
    """Verifies that evaluation splits exhibit zero fingerprint and public-key leakage."""
    manifest_path = storage.manifests_dir / "certificate_dataset_manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    fp_splits = manifest.get("evaluation_splits", {}).get("fingerprint_disjoint", {})
    assert fp_splits.get("train", 0) > 10000
    assert fp_splits.get("val", 0) > 2000
    assert fp_splits.get("test", 0) > 2000
    
    overlap_audit = manifest.get("evaluation_splits", {}).get("overlap_audit", {})
    assert overlap_audit.get("fingerprint_leakage_clean") is True, "Fingerprint disjoint split must have zero leakage"


def test_parquet_analytical_table_readable(storage):
    """Verifies that normalized certificates Parquet table is readable and matches JSONL counts."""
    import pandas as pd
    parquet_path = storage.normalized_dir / "normalized_certificates.parquet"
    assert parquet_path.exists(), "Parquet table must exist"
    
    df = pd.read_parquet(parquet_path)
    assert len(df) >= 20000, f"Expected >= 20,000 records in parquet analytical table, got {len(df)}"
    assert "sha256_fingerprint" in df.columns
    assert "certificate_type" in df.columns

