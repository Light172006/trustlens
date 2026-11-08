"""TrustLens Certificate Dataset Engineering Package.

This package provides ingestion, parsing, normalization, deduplication,
trust store reconciliation, chain construction, revocation observation,
multi-dimensional labeling, and dataset quality validation for X.509
certificate intelligence.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Automatically inject isolated .deps directory into sys.path if present
_DEPS_DIR = Path(__file__).resolve().parent.parent.parent / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

__version__ = "0.1.0"
__author__ = "TrustLens PKI & Data Engineering Team"

