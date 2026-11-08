"""
TrustLens Web Security Analyzer - Schema Validation Test Suite
Verifies that datasets conform to the declared Data Dictionary schema and typing rules.
"""

import json
from pathlib import Path
import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def data_dictionary():
    dict_path = BASE_DIR / "metadata" / "data_dictionary.json"
    with open(dict_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def processed_dataset():
    dataset_path = BASE_DIR / "dataset" / "processed" / "web_security_dataset.parquet"
    if not dataset_path.exists():
        pytest.skip(f"Processed dataset not yet generated at {dataset_path}")
    return pd.read_parquet(dataset_path)


def test_schema_required_columns(processed_dataset, data_dictionary):
    expected_cols = [col["name"] for col in data_dictionary["columns"]]
    for col_name in expected_cols:
        assert col_name in processed_dataset.columns, f"Required column '{col_name}' missing from dataset"


def test_schema_non_nullable_fields(processed_dataset, data_dictionary):
    for col_meta in data_dictionary["columns"]:
        col_name = col_meta["name"]
        if not col_meta.get("nullable", True) and col_name in processed_dataset.columns:
            null_count = processed_dataset[col_name].isna().sum()
            assert null_count == 0, f"Non-nullable column '{col_name}' contains {null_count} nulls"


def test_boolean_data_types(processed_dataset):
    bool_cols = [
        "domain_resolved", "dns_has_ipv4", "dns_has_ipv6", "dns_has_caa",
        "tls_supported", "tls_cert_valid", "tls_cert_expired", "tls_cert_is_self_signed",
        "tls_cert_hostname_match", "http_available", "https_available", "http_to_https_redirect",
        "https_downgrade", "header_hsts_present", "header_hsts_include_subdomains",
        "header_hsts_preload", "header_csp_present", "header_csp_unsafe_inline",
        "header_csp_unsafe_eval", "header_xfo_present", "header_xcto_present",
        "header_referrer_policy_present", "header_permissions_policy_present",
        "header_coop_present", "header_corp_present", "header_coep_present",
        "cookie_all_secure", "cookie_all_httponly", "server_version_exposed",
        "x_powered_by_present"
    ]
    for col in bool_cols:
        assert processed_dataset[col].dtype == bool, f"Column '{col}' expected bool, got {processed_dataset[col].dtype}"


def test_score_numeric_bounds(processed_dataset):
    scores = processed_dataset["website_posture_score"]
    assert scores.min() >= 0.0, f"Negative posture score found: {scores.min()}"
    assert scores.max() <= 100.0, f"Posture score exceeded 100.0: {scores.max()}"

