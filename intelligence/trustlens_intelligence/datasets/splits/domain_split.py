"""TrustLens Intelligence — Domain-Aware Disjoint Dataset Splitting.

Guarantees 0% data leakage across train, validation, and test splits by strictly
segregating whole registrable domains into mutually exclusive subsets.
"""

from dataclasses import dataclass
import random
from typing import Any
import pandas as pd


@dataclass
class SplitResult:
    """Disjoint dataset split containing DataFrames and partition domain lists."""

    train_df: pd.DataFrame
    val_df: pd.DataFrame
    test_df: pd.DataFrame
    train_domains: list[str]
    val_domains: list[str]
    test_domains: list[str]
    metadata: dict[str, Any]


def verify_zero_domain_leakage(split: SplitResult) -> bool:
    """Verify that there is strictly zero domain overlap across train, val, and test splits."""
    train_set = set(split.train_domains)
    val_set = set(split.val_domains)
    test_set = set(split.test_domains)

    leakage_train_val = train_set.intersection(val_set)
    leakage_train_test = train_set.intersection(test_set)
    leakage_val_test = val_set.intersection(test_set)

    if leakage_train_val or leakage_train_test or leakage_val_test:
        raise ValueError(
            f"Domain leakage detected! "
            f"Train/Val overlap: {len(leakage_train_val)}, "
            f"Train/Test overlap: {len(leakage_train_test)}, "
            f"Val/Test overlap: {len(leakage_val_test)}"
        )
    return True


class DomainSplitter:
    """Partitions datasets by registrable domain with optional label stratification."""

    def __init__(
        self,
        domain_column: str = "registrable_domain",
        label_column: str = "binary_label",
    ) -> None:
        self.domain_column = domain_column
        self.label_column = label_column

    def split(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        seed: int = 42,
        stratify: bool = True,
    ) -> SplitResult:
        """Split DataFrame into train, val, test subsets with zero domain overlap.

        Args:
            df: Source DataFrame containing domain_column.
            train_ratio: Proportion of unique domains allocated to training.
            val_ratio: Proportion of unique domains allocated to validation.
            test_ratio: Proportion of unique domains allocated to testing.
            seed: Random seed for reproducibility.
            stratify: If True, stratify domain partitioning by predominant label.

        Returns:
            SplitResult with disjoint partition DataFrames and domain lists.
        """
        if not (0.99 <= train_ratio + val_ratio + test_ratio <= 1.01):
            raise ValueError("Split ratios must sum to approximately 1.0")

        if self.domain_column not in df.columns:
            raise KeyError(f"Column '{self.domain_column}' not found in DataFrame")

        rng = random.Random(seed)

        train_domains: set[str] = set()
        val_domains: set[str] = set()
        test_domains: set[str] = set()

        # Stratified domain splitting by predominant label
        if stratify and self.label_column in df.columns:
            # Map each domain to its most frequent label
            domain_label_df = df[[self.domain_column, self.label_column]].drop_duplicates()
            # If multiple labels per domain, pick the first
            domain_to_label = domain_label_df.groupby(self.domain_column)[self.label_column].first().to_dict()

            label_groups: dict[Any, list[str]] = {}
            for dom, lbl in domain_to_label.items():
                label_groups.setdefault(lbl, []).append(dom)

            for lbl, doms in label_groups.items():
                rng.shuffle(doms)
                n = len(doms)
                if n < 3:
                    train_domains.update(doms)
                else:
                    n_train = int(n * train_ratio)
                    n_val = int(n * val_ratio)
                    train_domains.update(doms[:n_train])
                    val_domains.update(doms[n_train : n_train + n_val])
                    test_domains.update(doms[n_train + n_val :])
        else:
            unique_domains = list(df[self.domain_column].unique())
            rng.shuffle(unique_domains)
            total_domains = len(unique_domains)
            if total_domains < 3:
                train_cut = max(1, int(total_domains * train_ratio))
                val_cut = train_cut
                test_cut = total_domains
            else:
                train_cut = int(total_domains * train_ratio)
                val_cut = train_cut + int(total_domains * val_ratio)
                test_cut = total_domains

            train_domains = set(unique_domains[:train_cut])
            val_domains = set(unique_domains[train_cut:val_cut])
            test_domains = set(unique_domains[val_cut:test_cut])

        total_domains = len(df[self.domain_column].unique())

        # If val or test got 0 domains due to rounding, reallocate safely
        if not test_domains and len(train_domains) > 1:
            test_domains.add(train_domains.pop())
        if not val_domains and len(train_domains) > 1:
            val_domains.add(train_domains.pop())

        train_mask = df[self.domain_column].isin(train_domains)
        val_mask = df[self.domain_column].isin(val_domains)
        test_mask = df[self.domain_column].isin(test_domains)

        train_df = df[train_mask].reset_index(drop=True)
        val_df = df[val_mask].reset_index(drop=True)
        test_df = df[test_mask].reset_index(drop=True)

        result = SplitResult(
            train_df=train_df,
            val_df=val_df,
            test_df=test_df,
            train_domains=sorted(train_domains),
            val_domains=sorted(val_domains),
            test_domains=sorted(test_domains),
            metadata={
                "split_type": "domain_aware_disjoint",
                "train_ratio": train_ratio,
                "val_ratio": val_ratio,
                "test_ratio": test_ratio,
                "total_domains": total_domains,
                "train_sample_count": len(train_df),
                "val_sample_count": len(val_df),
                "test_sample_count": len(test_df),
            },
        )

        verify_zero_domain_leakage(result)
        return result

