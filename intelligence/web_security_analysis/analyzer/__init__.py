"""
TrustLens Web Security Analyzer Package
"""

import sys
from pathlib import Path

# Add current directory and parent to sys.path to allow flexible package and direct module imports
CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

from engine import WebSecurityAnalyzer
from models import (
    ConsensusModel,
    FindingsSummaryModel,
    MLPredictionModel,
    RemediationItemModel,
    SecurityFindingModel,
    WebSecurityReport,
)

__all__ = [
    "WebSecurityAnalyzer",
    "WebSecurityReport",
    "SecurityFindingModel",
    "MLPredictionModel",
    "ConsensusModel",
    "FindingsSummaryModel",
    "RemediationItemModel",
]

