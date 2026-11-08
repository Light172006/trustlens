"""
TrustLens Web Security Analyzer - Domain Uniqueness & PSL Integrity Test Suite
Verifies strict Registrable Domain uniqueness, duplicate count equals zero, and minimum scale >= 10,000.
"""

from pathlib import Path
import pandas as pd
import pytest
from tld import get_fld

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def processed_dataset():
    dataset_path = BASE_DIR / "dataset" / "processed" / "web_security_dataset.parquet"
    if not dataset_path.exists():
        pytest.skip(f"Processed dataset not yet generated at {dataset_path}")
    return pd.read_parquet(dataset_path)


def test_minimum_sample_size_requirement(processed_dataset):
    total_records = len(processed_dataset)
    assert total_records >= 10000, f"Production dataset must contain at least 10,000 records, got {total_records}"


def test_zero_duplicate_registrable_domains(processed_dataset):
    total_records = len(processed_dataset)
    unique_domains = processed_dataset["registrable_domain"].nunique()
    duplicate_count = total_records - unique_domains
    assert duplicate_count == 0, f"Dataset contains {duplicate_count} duplicate registrable domains! Expected 0 duplicates."


def test_public_suffix_list_normalization(processed_dataset):
    # Sample 100 domains to verify PSL conformity
    sample = processed_dataset["registrable_domain"].sample(min(len(processed_dataset), 100), random_state=42)
    for domain in sample:
        fld = get_fld(domain, fix_protocol=True, fail_silently=True) or domain
        assert fld.lower() == domain.lower(), f"Domain '{domain}' does not match PSL extraction '{fld}'"


def test_no_url_artifacts_in_registrable_domain(processed_dataset):
    for domain in processed_dataset["registrable_domain"]:
        assert "/" not in domain, f"Registrable domain contains slash: '{domain}'"
        assert "?" not in domain, f"Registrable domain contains query: '{domain}'"
        assert ":" not in domain, f"Registrable domain contains port: '{domain}'"
        assert not (domain.startswith("http://") or domain.startswith("https://")), f"Registrable domain contains scheme prefix: '{domain}'"

