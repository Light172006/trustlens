"""Evaluation metrics, calibration assessment, and generalization gap analysis."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Dict, Optional

# Ensure isolated .deps is available
_INTELLIGENCE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
_DEPS_DIR = _INTELLIGENCE_DIR / "certificate_dataset" / ".deps"
if _DEPS_DIR.exists() and str(_DEPS_DIR) not in sys.path:
    sys.path.insert(0, str(_DEPS_DIR))

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    brier_score_loss,
)


class CertificateMLEvaluator:
    """Computes comprehensive classification and calibration metrics."""

    @classmethod
    def evaluate(
        cls,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """Calculates multi-dimensional performance metrics."""
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        metrics: Dict[str, Any] = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp),
            },
        }

        if y_prob is not None:
            try:
                metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
                metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
                metrics["brier_score"] = float(brier_score_loss(y_true, y_prob))
            except Exception:
                metrics["roc_auc"] = None
                metrics["pr_auc"] = None
                metrics["brier_score"] = None

        return metrics

    @classmethod
    def compute_generalization_gap(
        cls,
        train_metrics: Dict[str, Any],
        val_metrics: Dict[str, Any],
        test_metrics: Dict[str, Any],
    ) -> Dict[str, float]:
        """Measures generalization drops from train to val and locked test."""
        return {
            "train_to_val_macro_f1_gap": float(train_metrics["macro_f1"] - val_metrics["macro_f1"]),
            "train_to_test_macro_f1_gap": float(train_metrics["macro_f1"] - test_metrics["macro_f1"]),
            "val_to_test_macro_f1_gap": float(val_metrics["macro_f1"] - test_metrics["macro_f1"]),
        }

