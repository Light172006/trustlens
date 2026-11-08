"""
TrustLens Web Security Analyzer - Deduplication Engine
Enforces strict Registrable-Domain level uniqueness.
Guarantees duplicate domain count is zero in final datasets.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_deduplicator")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def calculate_record_completeness(record: Dict[str, Any]) -> int:
    """Calculates an information completeness score to select the best record among duplicates."""
    score = 0
    if record.get("https_available"):
        score += 50
    if record.get("tls_cert_valid"):
        score += 30
    if record.get("http_available"):
        score += 10
    if record.get("header_hsts_present"):
        score += 5
    if record.get("header_csp_present"):
        score += 5
    if record.get("cookie_count", 0) > 0:
        score += 5
    return score


def deduplicate_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates records strictly on registrable_domain.
    If multiple observations share the same registrable domain, picks the one with highest completeness.
    """
    domain_map: Dict[str, Dict[str, Any]] = {}
    duplicate_counter = 0

    for rec in records:
        fld = rec["registrable_domain"].lower()
        if fld not in domain_map:
            domain_map[fld] = rec
        else:
            duplicate_counter += 1
            existing_score = calculate_record_completeness(domain_map[fld])
            new_score = calculate_record_completeness(rec)
            if new_score > existing_score:
                domain_map[fld] = rec

    deduped = list(domain_map.values())
    logger.info(f"Deduplication complete: {len(records)} input -> {len(deduped)} unique registrable domains. (Dropped {duplicate_counter} duplicates)")
    return deduped


def main():
    parser = argparse.ArgumentParser(description="TrustLens Deduplication Engine")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()


if __name__ == "__main__":
    main()

