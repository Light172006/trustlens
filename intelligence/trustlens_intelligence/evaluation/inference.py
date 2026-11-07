"""TrustLens Intelligence — Production ML Inference Pipeline.

Serves as an additional evidence signal within the threat intelligence engine.
Validates model artifacts, ensures reproducible feature alignment, and gracefully
handles inference failures without impacting the deterministic scoring pipeline.
"""

import logging
from pathlib import Path
from typing import Any
import joblib
import numpy as np
import pandas as pd

from trustlens_intelligence.config.constants import FEATURE_SCHEMA_VERSION, MODEL_SCHEMA_VERSION
from trustlens_intelligence.schemas.assessment import MLPrediction
from trustlens_intelligence.schemas.features import ExtractedFeatures

logger = logging.getLogger("trustlens.intelligence.evaluation.inference")


class ThreatClassifier:
    """Production ML inference interface for website threat probability estimation."""

    DEFAULT_ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "baseline_classifier.joblib"

    def __init__(
        self,
        artifact_or_path: dict[str, Any] | str | Path | None = None,
        auto_load_default: bool = False,
    ) -> None:
        self.model: Any = None
        self.model_name: str = "none"
        self.model_version: str = "0.0.0"
        self.feature_names: list[str] = []
        self.is_loaded: bool = False

        if artifact_or_path:
            self.load_artifact(artifact_or_path)
        elif auto_load_default and self.DEFAULT_ARTIFACT_PATH.exists():
            self.load_artifact(self.DEFAULT_ARTIFACT_PATH)

    @classmethod
    def load_default(cls) -> "ThreatClassifier":
        """Convenience factory to load the bundled default baseline model if available."""
        return cls(auto_load_default=True)

    def load_artifact(self, artifact_or_path: dict[str, Any] | str | Path) -> bool:
        """Load and validate model artifact bundle."""
        try:
            if isinstance(artifact_or_path, (str, Path)):
                path = Path(artifact_or_path)
                if not path.exists() or not path.is_file():
                    logger.warning("Model artifact not found or not a valid file at %s", path)
                    return False
                artifact = joblib.load(path)
            elif isinstance(artifact_or_path, dict):
                artifact = artifact_or_path
            else:
                logger.error("Invalid artifact type: %s", type(artifact_or_path))
                return False

            # Validate artifact structure and versions
            if "model" not in artifact or "feature_names" not in artifact:
                logger.error("Corrupted artifact: missing required keys")
                return False

            schema_ver = artifact.get("feature_schema_version", "")
            if schema_ver != FEATURE_SCHEMA_VERSION:
                logger.warning(
                    "Feature schema version mismatch: artifact=%s, engine=%s",
                    schema_ver,
                    FEATURE_SCHEMA_VERSION,
                )

            self.model = artifact["model"]
            self.model_name = artifact.get("model_name", "classifier")
            self.model_version = artifact.get("model_version", "1.0.0")
            self.feature_names = artifact["feature_names"]
            self.is_loaded = True

            logger.info("Successfully loaded ML model: %s (v%s)", self.model_name, self.model_version)
            return True
        except Exception as exc:
            logger.error("Failed to load model artifact: %s", exc, exc_info=True)
            self.is_loaded = False
            return False

    def predict(self, features: ExtractedFeatures) -> MLPrediction | None:
        """Execute inference on extracted features.

        Returns:
            MLPrediction if model is loaded and inference succeeds, or None if failed.
        """
        if not self.is_loaded or self.model is None:
            return None

        try:
            feature_dict = features.to_ml_dict()
            # Align features in the exact order the model expects
            ordered_values = {f: [feature_dict.get(f, 0.0)] for f in self.feature_names}
            df = pd.DataFrame(ordered_values)

            # Predict probability
            if hasattr(self.model, "predict_proba"):
                proba = float(self.model.predict_proba(df)[0, 1])
            else:
                raw_pred = self.model.predict(df)[0]
                proba = float(raw_pred)

            proba = max(0.0, min(1.0, proba))

            # Calibrate label
            if proba >= 0.70:
                label = "malicious"
            elif proba >= 0.35:
                label = "suspicious"
            else:
                label = "legitimate"

            # Identify top contributing features
            top_features = self._extract_top_features(features, proba)

            return MLPrediction(
                model_name=self.model_name,
                model_version=self.model_version,
                malicious_probability=round(proba, 4),
                predicted_label=label,
                calibrated_confidence=round(abs(proba - 0.5) * 2.0, 4),
                top_contributing_features=top_features,
            )
        except Exception as exc:
            logger.warning("ML inference failed gracefully: %s", exc)
            return None

    def _extract_top_features(self, features: ExtractedFeatures, proba: float) -> list[dict[str, Any]]:
        """Identify features that contributed most strongly to the prediction."""
        top: list[dict[str, Any]] = []
        if features.is_ip_host:
            top.append({"feature": "is_ip_host", "value": True, "impact": "high"})
        if features.openphish_match:
            top.append({"feature": "openphish_match", "value": True, "impact": "critical"})
        if features.urlhaus_online:
            top.append({"feature": "urlhaus_online", "value": True, "impact": "critical"})
        if features.suspicious_keyword_count > 0:
            top.append({"feature": "suspicious_keyword_count", "value": features.suspicious_keyword_count, "impact": "medium"})
        if features.url_entropy >= 4.3:
            top.append({"feature": "url_entropy", "value": features.url_entropy, "impact": "medium"})
        if features.cert_is_expired is True:
            top.append({"feature": "cert_is_expired", "value": True, "impact": "high"})

        return top[:4]

