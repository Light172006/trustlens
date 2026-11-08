"""
TrustLens Web Security Analyzer - Model Probability Calibration Engine
Implements Platt scaling (sigmoid) and isotonic regression to calibrate model confidence probabilities.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss

logger = logging.getLogger("calibration")


def compute_multiclass_brier_score(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    class_labels: List[str],
) -> float:
    """Computes multiclass Brier score across one-hot encoded classes."""
    n_classes = len(class_labels)
    brier_scores = []
    for idx, c in enumerate(class_labels):
        binary_true = (y_true == c).astype(float)
        binary_prob = y_proba[:, idx]
        brier_scores.append(brier_score_loss(binary_true, binary_prob))
    return float(np.mean(brier_scores))


def calibrate_model(
    base_model: Any,
    X_val: np.ndarray,
    y_val: np.ndarray,
    class_labels: List[str],
    method: str = "sigmoid",
) -> Tuple[Any, Dict[str, Any]]:
    """
    Fits a CalibratedClassifierCV wrapper on the validation set.
    Supports scikit-learn 1.9+ (FrozenEstimator) and legacy prefit cv.
    """
    logger.info(f"Calibrating model using method='{method}' on {len(X_val)} validation samples...")

    # Pre-calibration probabilities and Brier score
    pre_proba = base_model.predict_proba(X_val)
    pre_brier = compute_multiclass_brier_score(y_val, pre_proba, class_labels)

    try:
        from sklearn.frozen import FrozenEstimator
        calibrator = CalibratedClassifierCV(estimator=FrozenEstimator(base_model), method=method)
    except ImportError:
        calibrator = CalibratedClassifierCV(estimator=base_model, method=method, cv="prefit")

    calibrator.fit(X_val, y_val)

    post_proba = calibrator.predict_proba(X_val)
    post_brier = compute_multiclass_brier_score(y_val, post_proba, class_labels)

    logger.info(f"Brier score: pre={pre_brier:.4f} -> post={post_brier:.4f} (improvement={pre_brier - post_brier:.4f})")

    calibration_metrics = {
        "method": method,
        "pre_brier_score": round(pre_brier, 4),
        "post_brier_score": round(post_brier, 4),
        "improvement": round(pre_brier - post_brier, 4),
    }

    return calibrator, calibration_metrics
