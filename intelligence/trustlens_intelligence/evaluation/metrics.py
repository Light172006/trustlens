"""TrustLens Intelligence — Model Evaluation Metrics.

Computes precision, recall, F1, confusion matrix, PR-AUC, ROC-AUC, FPR, FNR,
and calibration metrics for trustworthy threat detection performance.
"""

from dataclasses import asdict, dataclass
from typing import Any
import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass
class EvaluationMetrics:
    """Comprehensive performance evaluation metrics for classification."""

    model_name: str
    sample_count: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    pr_auc: float
    roc_auc: float
    false_positive_rate: float
    false_negative_rate: float
    brier_score: float
    confusion_matrix: list[list[int]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_classification_metrics(
    y_true: np.ndarray | list[int],
    y_pred: np.ndarray | list[int],
    y_proba: np.ndarray | list[float],
    model_name: str = "model",
) -> EvaluationMetrics:
    """Compute all standard evaluation metrics for threat detection.

    Args:
        y_true: Ground truth binary labels (0 = benign, 1 = malicious).
        y_pred: Predicted binary labels.
        y_proba: Predicted probability of positive class (malicious).
        model_name: Name of model for reporting.

    Returns:
        Populated EvaluationMetrics dataclass.
    """
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    y_proba_arr = np.array(y_proba)

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))
    acc = float((tp + tn) / len(y_true_arr)) if len(y_true_arr) > 0 else 0.0

    # AUC metrics
    try:
        roc_auc = float(roc_auc_score(y_true_arr, y_proba_arr))
    except Exception:
        roc_auc = 0.5

    try:
        pr_auc = float(average_precision_score(y_true_arr, y_proba_arr))
    except Exception:
        pr_auc = 0.5

    try:
        brier = float(brier_score_loss(y_true_arr, y_proba_arr))
    except Exception:
        brier = 0.5

    return EvaluationMetrics(
        model_name=model_name,
        sample_count=len(y_true_arr),
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        pr_auc=round(pr_auc, 4),
        roc_auc=round(roc_auc, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        brier_score=round(brier, 4),
        confusion_matrix=cm.tolist(),
    )

