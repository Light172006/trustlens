"""
TrustLens Web Security Analyzer - Package Execution Entrypoint
Allows running: python -m analyzer [URL] from within intelligence/web_security_analysis/
"""

import sys
from pathlib import Path

ANALYZER_DIR = Path(__file__).resolve().parent
if str(ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZER_DIR))

from cli import main

if __name__ == "__main__":
    main()

