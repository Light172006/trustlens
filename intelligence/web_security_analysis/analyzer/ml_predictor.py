"""
TrustLens Web Security Analyzer - ML Posture Predictor & Abstention Engine
Loads calibrated model pipeline, performs inference on extracted features,
evaluates confidence, and triggers abstention when observations are incomplete or uncertain.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# Add training module to path for unpickling preprocessor classes
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "training"))

from model_registry import load_model_artifacts

logger = logging.getLogger("ml_predictor")


class MLSecurityPosturePredictor:
    """
    Manages model lifecycle, feature transformation, probability calibration,
    and confidence-based abstention logic.
    """

    def __init__(
        self,
        confidence_threshold: float = 0.55,
        margin_threshold: float = 0.10,
        models_dir: Optional[Path] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.margin_threshold = margin_threshold
        self.models_dir = models_dir
        self.model = None
        self.preprocessor = None
        self.metadata = None
        self._load_model()

    def _load_model(self) -> None:
        try:
            self.model, self.preprocessor, self.metadata = load_model_artifacts(
                models_dir=self.models_dir, verify_checksums=True
            )
            logger.info("ML Security Posture Predictor successfully initialized.")
        except Exception as e:
            logger.warning(f"Could not load ML model artifacts: {e}. Running in deterministic-only mode.")
            self.model = None
            self.preprocessor = None
            self.metadata = None

    @property
    def is_available(self) -> bool:
        return self.model is not None and self.preprocessor is not None

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes model prediction on a live feature dictionary.
        Returns predicted class, calibrated probabilities, confidence, and abstention status.
        """
        if not self.is_available:
            return {
                "available": False,
                "predicted_posture": "INSUFFICIENT_EVIDENCE",
                "probabilities": {},
                "confidence": 0.0,
                "abstained": True,
                "abstention_reason": "ML model artifact not loaded or unavailable.",
            }

        # 1. Structural Abstention Checks (incomplete scans, DNS failure, unreachable)
        if not features.get("domain_resolved", False):
            return {
                "available": True,
                "predicted_posture": "INSUFFICIENT_EVIDENCE",
                "probabilities": {},
                "confidence": 0.0,
                "abstained": True,
                "abstention_reason": "Domain resolution failed; insufficient technical evidence for ML inference.",
            }

        if features.get("collection_status") in ("UNREACHABLE", "DNS_FAILURE"):
            return {
                "available": True,
                "predicted_posture": "INSUFFICIENT_EVIDENCE",
                "probabilities": {},
                "confidence": 0.0,
                "abstained": True,
                "abstention_reason": "Target host was completely unreachable; observation is incomplete.",
            }

        # 2. Transform Features
        try:
            feature_df = pd.DataFrame([features])
            X_trans = self.preprocessor.transform(feature_df)
        except Exception as e:
            logger.error(f"Feature transformation error during inference: {e}")
            return {
                "available": True,
                "predicted_posture": "INSUFFICIENT_EVIDENCE",
                "probabilities": {},
                "confidence": 0.0,
                "abstained": True,
                "abstention_reason": f"Feature transformation failed: {e}",
            }

        # 3. Model Inference & Probabilities
        try:
            classes = list(self.model.classes_)
            probas = self.model.predict_proba(X_trans)[0]
            prob_dict = {classes[i]: round(float(probas[i]), 4) for i in range(len(classes))}

            top_idx = int(np.argmax(probas))
            top_class = classes[top_idx]
            top_prob = float(probas[top_idx])

            # Confidence margin between top two classes
            sorted_probs = sorted(probas, reverse=True)
            margin = sorted_probs[0] - sorted_probs[1] if len(sorted_probs) > 1 else sorted_probs[0]

            abstained = False
            abstention_reason = None

            # Low confidence or narrow margin abstention
            if top_prob < self.confidence_threshold:
                abstained = True
                abstention_reason = f"Prediction confidence ({top_prob:.2f}) below threshold ({self.confidence_threshold:.2f})."
            elif margin < self.margin_threshold:
                abstained = True
                abstention_reason = f"Confidence margin ({margin:.2f}) between top classes below threshold ({self.margin_threshold:.2f})."

            return {
                "available": True,
                "predicted_posture": top_class,
                "probabilities": prob_dict,
                "confidence": round(top_prob, 4),
                "margin": round(margin, 4),
                "abstained": abstained,
                "abstention_reason": abstention_reason,
                "model_name": self.metadata.get("model_name"),
                "model_version": self.metadata.get("model_version"),
            }
        except Exception as e:
            logger.error(f"Prediction inference error: {e}")
            return {
                "available": True,
                "predicted_posture": "INSUFFICIENT_EVIDENCE",
                "probabilities": {},
                "confidence": 0.0,
                "abstained": True,
                "abstention_reason": f"Inference execution failed: {e}",
            }

