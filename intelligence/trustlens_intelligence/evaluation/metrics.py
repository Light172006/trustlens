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


@dataclass
class MulticlassEvaluationMetrics:
    """Comprehensive performance metrics for 3-class URL threat detection."""

    model_name: str
    sample_count: int
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    per_class: dict[str, dict[str, float]]
    confusion_matrix: list[list[int]]
    ovr_roc_auc: float
    ovr_pr_auc: float
    multiclass_brier_score: float
    expected_calibration_error: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_expected_calibration_error(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    n_bins: int = 10,
) -> float:
    """Compute Expected Calibration Error (ECE) for multi-class predictions."""
    confidences = np.max(y_proba, axis=1)
    predictions = np.argmax(y_proba, axis=1)
    accuracies = predictions == y_true

    ece = 0.0
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    n = len(y_true)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
        prop_in_bin = np.mean(in_bin)

        if prop_in_bin > 0:
            accuracy_in_bin = np.mean(accuracies[in_bin])
            avg_confidence_in_bin = np.mean(confidences[in_bin])
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

    return float(ece)


def compute_multiclass_metrics(
    y_true: np.ndarray | list[int],
    y_pred: np.ndarray | list[int],
    y_proba: np.ndarray,
    model_name: str = "multiclass_model",
    class_names: tuple[str, ...] = ("legitimate", "phishing", "malware"),
) -> MulticlassEvaluationMetrics:
    """Compute evaluation metrics for 3-class URL classification."""
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)
    y_proba_arr = np.array(y_proba)
    num_classes = len(class_names)

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=list(range(num_classes)))
    acc = float(np.mean(y_true_arr == y_pred_arr))

    macro_prec = float(precision_score(y_true_arr, y_pred_arr, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true_arr, y_pred_arr, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true_arr, y_pred_arr, average="macro", zero_division=0))

    per_class: dict[str, dict[str, float]] = {}
    for i, name in enumerate(class_names):
        c_true = (y_true_arr == i).astype(int)
        c_pred = (y_pred_arr == i).astype(int)
        p = float(precision_score(c_true, c_pred, zero_division=0))
        r = float(recall_score(c_true, c_pred, zero_division=0))
        f = float(f1_score(c_true, c_pred, zero_division=0))
        per_class[name] = {
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f, 4),
            "support": int(np.sum(c_true)),
        }

    # OVR AUC metrics
    try:
        from sklearn.preprocessing import label_binarize
        y_bin = label_binarize(y_true_arr, classes=list(range(num_classes)))
        ovr_roc = float(roc_auc_score(y_bin, y_proba_arr, multi_class="ovr", average="macro"))
    except Exception:
        ovr_roc = 0.5

    try:
        ovr_pr = float(average_precision_score(y_bin, y_proba_arr, average="macro"))
    except Exception:
        ovr_pr = 0.5

    # Multi-class Brier score: mean squared difference across all classes
    try:
        y_one_hot = np.zeros_like(y_proba_arr)
        for i in range(len(y_true_arr)):
            y_one_hot[i, y_true_arr[i]] = 1.0
        multi_brier = float(np.mean(np.sum((y_proba_arr - y_one_hot) ** 2, axis=1)))
    except Exception:
        multi_brier = 0.5

    ece = compute_expected_calibration_error(y_true_arr, y_proba_arr)

    return MulticlassEvaluationMetrics(
        model_name=model_name,
        sample_count=len(y_true_arr),
        accuracy=round(acc, 4),
        macro_precision=round(macro_prec, 4),
        macro_recall=round(macro_rec, 4),
        macro_f1=round(macro_f1, 4),
        per_class=per_class,
        confusion_matrix=cm.tolist(),
        ovr_roc_auc=round(ovr_roc, 4),
        ovr_pr_auc=round(ovr_pr, 4),
        multiclass_brier_score=round(multi_brier, 4),
        expected_calibration_error=round(ece, 4),
    )


