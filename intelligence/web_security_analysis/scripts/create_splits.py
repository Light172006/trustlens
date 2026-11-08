"""
TrustLens Web Security Analyzer - Zero-Leakage Dataset Splitting Engine
Partitions dataset into Train (70%), Validation (15%), and Test (15%) splits
strictly partitioned at the Registrable Domain level with zero data leakage.
"""

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("web_security_splitter")

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    if config_path is None:
        config_path = str(BASE_DIR / "config.yaml")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def create_zero_leakage_splits(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Partitions the dataset strictly by unique registrable_domain with stratification by posture label.
    Guarantees: set(train_domains) & set(val_domains) & set(test_domains) == empty set.
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-5, "Split ratios must sum to 1.0"

    np.random.seed(random_seed)

    # Unique registrable domains
    unique_domains_df = df[["registrable_domain", "website_posture_label"]].drop_duplicates(subset=["registrable_domain"])

    train_domains = set()
    val_domains = set()
    test_domains = set()

    # Stratified domain assignment across posture classes
    for label, group in unique_domains_df.groupby("website_posture_label"):
        domains = group["registrable_domain"].sample(frac=1.0, random_state=random_seed).values
        n = len(domains)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train_domains.update(domains[:n_train])
        val_domains.update(domains[n_train : n_train + n_val])
        test_domains.update(domains[n_train + n_val :])

    # Assign splits
    train_df = df[df["registrable_domain"].isin(train_domains)].copy().reset_index(drop=True)
    val_df = df[df["registrable_domain"].isin(val_domains)].copy().reset_index(drop=True)
    test_df = df[df["registrable_domain"].isin(test_domains)].copy().reset_index(drop=True)

    # Verification of zero leakage
    train_set = set(train_df["registrable_domain"])
    val_set = set(val_df["registrable_domain"])
    test_set = set(test_df["registrable_domain"])

    overlap_train_val = train_set & val_set
    overlap_train_test = train_set & test_set
    overlap_val_test = val_set & test_set

    assert len(overlap_train_val) == 0, f"Leakage detected between Train and Val: {len(overlap_train_val)} domains"
    assert len(overlap_train_test) == 0, f"Leakage detected between Train and Test: {len(overlap_train_test)} domains"
    assert len(overlap_val_test) == 0, f"Leakage detected between Val and Test: {len(overlap_val_test)} domains"

    logger.info(f"Split Generation Summary (Zero Leakage Verified):")
    logger.info(f"  Train:      {len(train_df)} rows ({len(train_set)} unique domains) [{len(train_df)/len(df)*100:.1f}%]")
    logger.info(f"  Validation: {len(val_df)} rows ({len(val_set)} unique domains) [{len(val_df)/len(df)*100:.1f}%]")
    logger.info(f"  Test:       {len(test_df)} rows ({len(test_set)} unique domains) [{len(test_df)/len(df)*100:.1f}%]")

    return train_df, val_df, test_df


def save_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    config: Dict[str, Any],
) -> None:
    splits_dir = BASE_DIR / config["paths"]["splits_dir"]
    splits_dir.mkdir(parents=True, exist_ok=True)

    train_path = splits_dir / "train.parquet"
    val_path = splits_dir / "validation.parquet"
    test_path = splits_dir / "test.parquet"

    train_df.to_parquet(train_path, index=False, engine="pyarrow")
    val_df.to_parquet(val_path, index=False, engine="pyarrow")
    test_df.to_parquet(test_path, index=False, engine="pyarrow")

    logger.info(f"Saved zero-leakage splits to {splits_dir}")


def main():
    parser = argparse.ArgumentParser(description="TrustLens Split Generation")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()


if __name__ == "__main__":
    main()

