"""Pytest configuration and fixture loading."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure package src and isolated .deps are on sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _ROOT / "src"
_DEPS_DIR = _ROOT / ".deps"

if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

import pytest
from certificate_dataset.quality.fixtures import TestFixtureGenerator


@pytest.fixture(scope="session")
def synthetic_fixtures():
    fixtures_file = _ROOT / "tests" / "fixtures" / "synthetic_test_fixtures.jsonl"
    if not fixtures_file.exists():
        TestFixtureGenerator.generate_all_fixtures(fixtures_file.parent)
    fixtures = []
    with open(fixtures_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                fixtures.append(json.loads(line_str))
    return fixtures

