"""
TrustLens Web Security Analyzer - Module Entry Point
Invoked when running: python -m intelligence.web_security_analysis [URL]
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ANALYZER_DIR = BASE_DIR / "analyzer"
if str(ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZER_DIR))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from cli import main

if __name__ == "__main__":
    main()

