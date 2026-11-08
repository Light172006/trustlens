"""Feature engineering and preprocessing pipeline for Certificate ML."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import List

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


NUMERIC_FEATURES: List[str] = [
    "key_size_bits",
    "validity_duration_days",
    "san_count",
    "is_wildcard",
    "has_scts",
    "sct_count",
    "extension_count",
    "key_usage_count",
    "extended_key_usage_count",
    "is_ca",
    "is_self_signed",
    "subject_dn_length",
]

CATEGORICAL_FEATURES: List[str] = [
    "key_algorithm",
    "ec_curve",
    "signature_algorithm",
]

# Strict forbidden keywords to prevent target leakage
PROHIBITED_FEATURE_SUBSTRINGS: List[str] = [
    "score",
    "finding",
    "deduction",
    "verdict",
    "policy_compliant",
    "weak_",
    "is_valid",
    "is_trusted",
    "rule_",
]


class CertificateFeaturePreprocessor:
    """Creates leakage-free feature transformation pipelines for raw certificate parameters."""

    @classmethod
    def validate_feature_names(cls, feature_names: List[str]) -> None:
        """Enforces that no rule outputs or target signals leak into features."""
        for feat in feature_names:
            feat_lower = feat.lower()
            for prohibited in PROHIBITED_FEATURE_SUBSTRINGS:
                if prohibited in feat_lower:
                    raise ValueError(
                        f"Target leakage violation: feature '{feat}' contains prohibited substring '{prohibited}'"
                    )

    @classmethod
    def build_transformer(cls) -> ColumnTransformer:
        """Builds a scikit-learn ColumnTransformer for standardizing and encoding."""
        cls.validate_feature_names(NUMERIC_FEATURES + CATEGORICAL_FEATURES)

        transformer = ColumnTransformer(
            transformers=[
                ("num", StandardScaler(), NUMERIC_FEATURES),
                ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES),
            ],
            remainder="drop",
        )
        return transformer

