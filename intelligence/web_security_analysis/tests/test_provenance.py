"""
TrustLens Web Security Analyzer - Provenance & Privacy Test Suite
Verifies source attribution, observation timestamps, and zero leakage of raw cookie values or tokens.
"""

from pathlib import Path
import re
import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def processed_dataset():
    dataset_path = BASE_DIR / "dataset" / "processed" / "web_security_dataset.parquet"
    if not dataset_path.exists():
        pytest.skip(f"Processed dataset not yet generated at {dataset_path}")
    return pd.read_parquet(dataset_path)


def test_provenance_fields_populated(processed_dataset):
    assert (processed_dataset["source_name"].str.len() > 0).all(), "Found empty source_name"
    assert (processed_dataset["scan_timestamp"].str.len() > 0).all(), "Found empty scan_timestamp"
    assert (processed_dataset["collection_method"].str.len() > 0).all(), "Found empty collection_method"
    assert (processed_dataset["dataset_version"].str.len() > 0).all(), "Found empty dataset_version"


def test_no_raw_cookie_values_stored(processed_dataset):
    # Dataframe columns should NOT include cookie values
    cookie_cols = [c for c in processed_dataset.columns if "cookie" in c.lower()]
    forbidden_cols = ["cookie_value", "cookie_names", "raw_cookies", "cookie_payload", "session_id"]
    for col in forbidden_cols:
        assert col not in processed_dataset.columns, f"Forbidden privacy-violating cookie column '{col}' detected!"


def test_no_credentials_or_tokens_in_headers(processed_dataset):
    token_pattern = re.compile(r"(bearer\s+[a-zA-Z0-9_\-\.]+|jwt\s+|token=[a-zA-Z0-9]+|secret=)", re.IGNORECASE)
    for header_val in processed_dataset["server_header"].dropna():
        assert not token_pattern.search(str(header_val)), f"Potential token or credential leaked in server header: {header_val}"


def test_iso_8601_timestamps(processed_dataset):
    iso_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
    for ts in processed_dataset["scan_timestamp"].sample(min(len(processed_dataset), 100), random_state=42):
        assert iso_pattern.match(str(ts)), f"Timestamp not in ISO 8601 format: {ts}"

