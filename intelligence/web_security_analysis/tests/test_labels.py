"""
TrustLens Web Security Analyzer - Finding Taxonomy & Posture Labeling Test Suite
Verifies finding taxonomy compliance, severity mappings, evidence completeness, and rubric scoring.
"""

import json
from pathlib import Path
import pandas as pd
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def taxonomy():
    tax_path = BASE_DIR / "metadata" / "label_taxonomy.json"
    with open(tax_path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def processed_dataset():
    dataset_path = BASE_DIR / "dataset" / "processed" / "web_security_dataset.parquet"
    if not dataset_path.exists():
        pytest.skip(f"Processed dataset not yet generated at {dataset_path}")
    return pd.read_parquet(dataset_path)


def test_website_posture_labels_taxonomy(processed_dataset, taxonomy):
    valid_labels = set(taxonomy["website_posture_rubric"].keys())
    actual_labels = set(processed_dataset["website_posture_label"].unique())
    invalid = actual_labels - valid_labels
    assert len(invalid) == 0, f"Found invalid website_posture_labels: {invalid}"


def test_evidence_presence_for_all_fail_findings(processed_dataset):
    sample = processed_dataset["findings"].dropna().sample(min(len(processed_dataset), 300), random_state=42)
    fail_count = 0
    for f_json in sample:
        findings = json.loads(f_json)
        for f in findings:
            if f.get("status") == "FAIL":
                fail_count += 1
                evidence = f.get("evidence", "")
                assert evidence and len(evidence.strip()) >= 5, f"Missing evidence for FAIL finding: {f.get('finding_id')}"
    assert fail_count > 0, "No FAIL findings found in sample to verify evidence presence."


def test_critical_failure_enforces_poor_posture(processed_dataset):
    # Any record with critical_findings_count > 0 must be labeled POOR
    crit_records = processed_dataset[processed_dataset["critical_findings_count"] > 0]
    if len(crit_records) > 0:
        non_poor = crit_records[crit_records["website_posture_label"] != "POOR"]
        assert len(non_poor) == 0, f"Found {len(non_poor)} records with CRITICAL findings not labeled POOR!"


def test_posture_score_consistency(processed_dataset):
    for _, row in processed_dataset.sample(min(len(processed_dataset), 200), random_state=42).iterrows():
        score = row["website_posture_score"]
        label = row["website_posture_label"]
        crit = row["critical_findings_count"]
        high = row["high_findings_count"]

        if label == "GOOD":
            assert score >= 80.0, f"GOOD label with score < 80 ({score})"
            assert crit == 0, "GOOD label with critical findings"
            assert high == 0, "GOOD label with high findings"
        elif label == "MODERATE":
            assert crit == 0, "MODERATE label with critical findings"
        elif label == "POOR":
            assert crit > 0 or score < 50.0, f"POOR label without critical finding or low score (score={score})"

