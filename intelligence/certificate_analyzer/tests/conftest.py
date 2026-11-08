"""Pytest configuration for certificate_analyzer tests."""

import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _ROOT / "src"
_DATASET_SRC = _ROOT.parent / "certificate_dataset" / "src"
_DATASET_DEPS = _ROOT.parent / "certificate_dataset" / ".deps"

for d in [_SRC_DIR, _DATASET_SRC, _DATASET_DEPS]:
    if d.exists() and str(d) not in sys.path:
        sys.path.insert(0, str(d))

import pytest
from certificate_dataset.quality.fixtures import TestFixtureGenerator


@pytest.fixture(scope="session")
def synthetic_fixtures():
    fixtures_file = _ROOT.parent / "certificate_dataset" / "tests" / "fixtures" / "synthetic_test_fixtures.jsonl"
    if not fixtures_file.exists():
        TestFixtureGenerator.generate_all_fixtures(fixtures_file.parent)
    fixtures = []
    with open(fixtures_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                fixtures.append(json.loads(line_str))
    return fixtures

