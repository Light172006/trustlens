"""
TrustLens Web Security Analyzer - Command Line Interface (CLI)
Provides human-readable and machine-readable CLI assessment commands for arbitrary website URLs.
"""

import argparse
import json
import sys
from pathlib import Path

# Setup paths
CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

from engine import WebSecurityAnalyzer
from feature_extractor import SafeLiveFeatureExtractor
from ml_predictor import MLSecurityPosturePredictor
from risk_aggregator import RiskAggregator


def main():
    parser = argparse.ArgumentParser(
        description="TrustLens Web Security Analyzer - Assess the technical security posture of any website.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", type=str, help="Target website URL or domain (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output full structured JSON report")
    parser.add_argument("--timeout", type=float, default=5.0, help="Total network observation timeout in seconds")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if security posture is POOR")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")

    args = parser.parse_args()

    extractor = SafeLiveFeatureExtractor(timeout_seconds=args.timeout)
    predictor = MLSecurityPosturePredictor()
    aggregator = RiskAggregator()
    analyzer = WebSecurityAnalyzer(extractor=extractor, predictor=predictor, aggregator=aggregator)

    report = analyzer.analyze(args.url)

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(report.to_summary_text())

    if args.strict and report.posture == "POOR":
        sys.exit(1)
    elif report.posture == "INSUFFICIENT_EVIDENCE":
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

