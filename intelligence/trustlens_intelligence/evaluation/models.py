"""TrustLens Intelligence — Baseline Machine Learning Models.

Implements baseline classifiers:
1. Logistic Regression (Linear baseline with scaling)
2. Random Forest (Ensemble tree baseline)
3. HistGradientBoosting (Gradient boosted trees)
"""

from typing import Any
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def build_logistic_regression_pipeline(
    max_iter: int = 1000,
    random_state: int = 42,
) -> Pipeline:
    """Build a scaled Logistic Regression pipeline."""
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=max_iter,
                    random_state=random_state,
                    class_weight="balanced",
                ),
            ),
        ]
    )


def build_random_forest_pipeline(
    n_estimators: int = 100,
    max_depth: int | None = 10,
    random_state: int = 42,
) -> Pipeline:
    """Build a Random Forest classifier pipeline."""
    return Pipeline(
        [
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=n_estimators,
                    max_depth=max_depth,
                    random_state=random_state,
                    class_weight="balanced",
                ),
            )
        ]
    )


def build_gradient_boosting_pipeline(
    max_iter: int = 100,
    random_state: int = 42,
) -> Pipeline:
    """Build a HistGradientBoosting classifier pipeline."""
    return Pipeline(
        [
            (
                "classifier",
                HistGradientBoostingClassifier(
                    max_iter=max_iter,
                    random_state=random_state,
                    class_weight="balanced",
                ),
            )
        ]
    )


def get_available_model_factories() -> dict[str, Any]:
    """Return dictionary of available baseline model builders."""
    return {
        "logistic_regression": build_logistic_regression_pipeline,
        "random_forest": build_random_forest_pipeline,
        "gradient_boosting": build_gradient_boosting_pipeline,
    }

