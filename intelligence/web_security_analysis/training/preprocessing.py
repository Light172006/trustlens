"""
TrustLens Web Security Analyzer - Feature Engineering & Preprocessing Pipeline
Transforms raw web security observations into model-ready numerical feature matrices.
Ensures zero data leakage by fitting exclusively on training sets.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

logger = logging.getLogger("preprocessing")

# Top server vendor signatures
SERVER_VENDORS = [
    ("cloudflare", re.compile(r"cloudflare", re.I)),
    ("nginx", re.compile(r"nginx", re.I)),
    ("apache", re.compile(r"apache", re.I)),
    ("gws", re.compile(r"(gws|google)", re.I)),
    ("microsoft-iis", re.compile(r"iis", re.I)),
    ("litespeed", re.compile(r"litespeed", re.I)),
    ("caddy", re.compile(r"caddy", re.I)),
    ("amazon", re.compile(r"(awselb|amazon)", re.I)),
]


def extract_server_vendor(server_header: Optional[str]) -> str:
    """Classifies server response banner into standardized vendor categories."""
    if not server_header or pd.isna(server_header) or str(server_header).strip() == "":
        return "MISSING"
    header_str = str(server_header).lower()
    for name, pattern in SERVER_VENDORS:
        if pattern.search(header_str):
            return name
    return "OTHER"


class WebSecurityFeatureEngineer(BaseEstimator, TransformerMixin):
    """
    Feature engineering step that creates derived features and normalizes missing data
    prior to column transformation.
    """

    def __init__(self, numerical_cols: List[str], boolean_cols: List[str], categorical_cols: List[str]):
        self.numerical_cols = numerical_cols
        self.boolean_cols = boolean_cols
        self.categorical_cols = categorical_cols

    def fit(self, X: pd.DataFrame, y=None):
        return self

    def transform(self, X: Union[pd.DataFrame, Dict[str, Any]]) -> pd.DataFrame:
        if isinstance(X, dict):
            df = pd.DataFrame([X])
        else:
            df = X.copy()

        # Derive server_vendor if not present
        if "server_vendor" not in df.columns:
            if "server_header" in df.columns:
                df["server_vendor"] = df["server_header"].apply(extract_server_vendor)
            else:
                df["server_vendor"] = "MISSING"

        # Ensure all expected columns exist
        for col in self.numerical_cols:
            if col not in df.columns:
                df[col] = np.nan
            else:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        for col in self.boolean_cols:
            if col not in df.columns:
                df[col] = 0.0
            else:
                df[col] = df[col].fillna(False).astype(float)

        for col in self.categorical_cols:
            if col not in df.columns:
                df[col] = "MISSING"
            else:
                df[col] = df[col].fillna("MISSING").astype(str)

        all_cols = self.numerical_cols + self.boolean_cols + self.categorical_cols
        return df[all_cols]


def create_preprocessor_pipeline(
    numerical_cols: List[str],
    boolean_cols: List[str],
    categorical_cols: List[str],
) -> Pipeline:
    """
    Constructs a complete scikit-learn Pipeline with feature engineering,
    imputation, scaling, and categorical encoding.
    """
    num_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])

    bool_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
    ])

    cat_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value="MISSING")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    col_transformer = ColumnTransformer(
        transformers=[
            ("num", num_pipeline, numerical_cols),
            ("bool", bool_pipeline, boolean_cols),
            ("cat", cat_pipeline, categorical_cols),
        ],
        remainder="drop",
    )

    full_pipeline = Pipeline([
        ("engineer", WebSecurityFeatureEngineer(numerical_cols, boolean_cols, categorical_cols)),
        ("transform", col_transformer),
    ])

    return full_pipeline

