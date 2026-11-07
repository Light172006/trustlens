"""TrustLens Intelligence — Temporal Out-of-Distribution Dataset Splitting.

Splits dataset chronologically to simulate realistic production deployment
and evaluate temporal drift on emerging, forward-looking threat campaigns.
"""

from datetime import datetime, timezone
from typing import Any
import pandas as pd

from trustlens_intelligence.datasets.splits.domain_split import SplitResult


class TemporalSplitter:
    """Partitions datasets chronologically based on observation or submission timestamps."""

    def __init__(
        self,
        timestamp_column: str = "timestamp",
        domain_column: str = "registrable_domain",
    ) -> None:
        self.timestamp_column = timestamp_column
        self.domain_column = domain_column

    def split_by_cutoffs(
        self,
        df: pd.DataFrame,
        val_cutoff: datetime,
        test_cutoff: datetime,
    ) -> SplitResult:
        """Split DataFrame strictly by temporal cutoff dates."""
        if self.timestamp_column not in df.columns:
            raise KeyError(f"Timestamp column '{self.timestamp_column}' not found in DataFrame")

        ts_series = pd.to_datetime(df[self.timestamp_column], utc=True)

        train_mask = ts_series < val_cutoff
        val_mask = (ts_series >= val_cutoff) & (ts_series < test_cutoff)
        test_mask = ts_series >= test_cutoff

        train_df = df[train_mask].reset_index(drop=True)
        val_df = df[val_mask].reset_index(drop=True)
        test_df = df[test_mask].reset_index(drop=True)

        train_domains = (
            sorted(train_df[self.domain_column].unique().tolist())
            if self.domain_column in train_df
            else []
        )
        val_domains = (
            sorted(val_df[self.domain_column].unique().tolist())
            if self.domain_column in val_df
            else []
        )
        test_domains = (
            sorted(test_df[self.domain_column].unique().tolist())
            if self.domain_column in test_df
            else []
        )

        return SplitResult(
            train_df=train_df,
            val_df=val_df,
            test_df=test_df,
            train_domains=train_domains,
            val_domains=val_domains,
            test_domains=test_domains,
            metadata={
                "split_type": "temporal_cutoff",
                "val_cutoff": val_cutoff.isoformat(),
                "test_cutoff": test_cutoff.isoformat(),
                "train_sample_count": len(train_df),
                "val_sample_count": len(val_df),
                "test_sample_count": len(test_df),
            },
        )

    def split_by_quantiles(
        self,
        df: pd.DataFrame,
        train_quantile: float = 0.70,
        val_quantile: float = 0.85,
    ) -> SplitResult:
        """Split DataFrame chronologically using timestamp quantiles."""
        if self.timestamp_column not in df.columns:
            raise KeyError(f"Timestamp column '{self.timestamp_column}' not found in DataFrame")

        ts_series = pd.to_datetime(df[self.timestamp_column], utc=True)
        sorted_df = df.sort_values(by=self.timestamp_column).reset_index(drop=True)

        total = len(sorted_df)
        train_end = int(total * train_quantile)
        val_end = int(total * val_quantile)

        train_df = sorted_df.iloc[:train_end].reset_index(drop=True)
        val_df = sorted_df.iloc[train_end:val_end].reset_index(drop=True)
        test_df = sorted_df.iloc[val_end:].reset_index(drop=True)

        train_domains = (
            sorted(train_df[self.domain_column].unique().tolist())
            if self.domain_column in train_df
            else []
        )
        val_domains = (
            sorted(val_df[self.domain_column].unique().tolist())
            if self.domain_column in val_df
            else []
        )
        test_domains = (
            sorted(test_df[self.domain_column].unique().tolist())
            if self.domain_column in test_df
            else []
        )

        return SplitResult(
            train_df=train_df,
            val_df=val_df,
            test_df=test_df,
            train_domains=train_domains,
            val_domains=val_domains,
            test_domains=test_domains,
            metadata={
                "split_type": "temporal_quantile",
                "train_quantile": train_quantile,
                "val_quantile": val_quantile,
                "train_sample_count": len(train_df),
                "val_sample_count": len(val_df),
                "test_sample_count": len(test_df),
            },
        )

