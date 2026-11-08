"""Candidate model definitions for Certificate ML classification and anomaly detection."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Dict

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, IsolationForest

from certificate_analyzer.ml.preprocessing import CertificateFeaturePreprocessor


class CertificateModelFactory:
    """Instantiates scikit-learn model pipelines."""

    @classmethod
    def get_candidate_models(cls) -> Dict[str, Pipeline]:
        """Returns standard supervised candidate classification pipelines."""
        preprocessor = CertificateFeaturePreprocessor.build_transformer()

        candidates: Dict[str, Pipeline] = {
            "logistic_regression": Pipeline([
                ("preprocessor", preprocessor),
                ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)),
            ]),
            "random_forest": Pipeline([
                ("preprocessor", preprocessor),
                ("classifier", RandomForestClassifier(
                    n_estimators=100,
                    max_depth=12,
                    min_samples_split=5,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                )),
            ]),
            "hist_gradient_boosting": Pipeline([
                ("preprocessor", preprocessor),
                ("classifier", HistGradientBoostingClassifier(
                    max_iter=100,
                    max_depth=8,
                    class_weight="balanced",
                    random_state=42,
                )),
            ]),
        }
        return candidates

    @classmethod
    def get_anomaly_detector(cls, contamination: float = 0.05) -> Pipeline:
        """Returns an unsupervised Isolation Forest pipeline for certificate profile anomaly detection."""
        preprocessor = CertificateFeaturePreprocessor.build_transformer()
        return Pipeline([
            ("preprocessor", preprocessor),
            ("detector", IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )),
        ])

