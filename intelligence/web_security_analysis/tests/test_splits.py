"""
TrustLens Web Security Analyzer - Zero-Leakage Splits Test Suite
Verifies train/validation/test domain isolation and absence of target leakage.
"""

from pathlib import Path
import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def splits():
    splits_dir = BASE_DIR / "dataset" / "splits"
    train_path = splits_dir / "train.parquet"
    val_path = splits_dir / "validation.parquet"
    test_path = splits_dir / "test.parquet"

    if not (train_path.exists() and val_path.exists() and test_path.exists()):
        pytest.skip(f"Splits not yet generated in {splits_dir}")

    return {
        "train": pd.read_parquet(train_path),
        "val": pd.read_parquet(val_path),
        "test": pd.read_parquet(test_path),
    }


def test_split_files_exist(splits):
    assert len(splits["train"]) > 0, "Train split is empty"
    assert len(splits["val"]) > 0, "Validation split is empty"
    assert len(splits["test"]) > 0, "Test split is empty"


def test_split_proportions(splits):
    n_train = len(splits["train"])
    n_val = len(splits["val"])
    n_test = len(splits["test"])
    total = n_train + n_val + n_test

    p_train = n_train / total
    p_val = n_val / total
    p_test = n_test / total

    # Tolerance within +/- 3%
    assert 0.67 <= p_train <= 0.73, f"Train proportion {p_train:.3f} outside expected [0.67, 0.73]"
    assert 0.12 <= p_val <= 0.18, f"Validation proportion {p_val:.3f} outside expected [0.12, 0.18]"
    assert 0.12 <= p_test <= 0.18, f"Test proportion {p_test:.3f} outside expected [0.12, 0.18]"


def test_zero_leakage_across_splits(splits):
    train_domains = set(splits["train"]["registrable_domain"])
    val_domains = set(splits["val"]["registrable_domain"])
    test_domains = set(splits["test"]["registrable_domain"])

    overlap_train_val = train_domains & val_domains
    overlap_train_test = train_domains & test_domains
    overlap_val_test = val_domains & test_domains

    assert len(overlap_train_val) == 0, f"Found {len(overlap_train_val)} overlapping domains between Train and Validation!"
    assert len(overlap_train_test) == 0, f"Found {len(overlap_train_test)} overlapping domains between Train and Test!"
    assert len(overlap_val_test) == 0, f"Found {len(overlap_val_test)} overlapping domains between Validation and Test!"


def test_no_target_label_in_features():
    # Model feature representation should not include derived posture labels or raw findings
    feature_cols = [
        "url_length", "subdomain_count", "is_idn", "is_ip_host", "domain_resolved",
        "dns_has_ipv4", "dns_has_ipv6", "dns_has_caa", "tls_supported", "tls_version",
        "tls_cipher", "tls_cert_valid", "tls_cert_expired", "tls_cert_remaining_days",
        "tls_cert_san_count", "tls_cert_is_self_signed", "tls_cert_hostname_match",
        "http_available", "https_available", "http_to_https_redirect", "redirect_count",
        "final_status_code", "final_scheme", "https_downgrade", "header_hsts_present",
        "header_hsts_max_age", "header_hsts_include_subdomains", "header_hsts_preload",
        "header_csp_present", "header_csp_unsafe_inline", "header_csp_unsafe_eval",
        "header_xfo_present", "header_xcto_present", "header_referrer_policy_present",
        "cookie_count", "cookie_secure_count", "cookie_httponly_count", "cookie_all_secure",
        "server_version_exposed", "x_powered_by_present"
    ]
    target_cols = [
        "website_posture_label", "website_posture_score", "findings", "finding_ids",
        "critical_findings_count", "high_findings_count", "medium_findings_count"
    ]
    leakage = set(feature_cols) & set(target_cols)
    assert len(leakage) == 0, f"Target columns leaked into features: {leakage}"

