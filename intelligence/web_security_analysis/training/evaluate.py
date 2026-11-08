"""
TrustLens Web Security Analyzer - Model Evaluation & Security Metrics Engine
Computes multi-class classification metrics, calibration error, and security-specific penalty metrics.
"""

from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_classifier_performance(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    class_labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes standard ML and security-specific metrics.
    """
    if class_labels is None:
        class_labels = sorted(list(set(y_true) | set(y_pred)))

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=class_labels)

    # Per-class metrics
    per_class_f1 = f1_score(y_true, y_pred, labels=class_labels, average=None, zero_division=0)
    per_class_prec = precision_score(y_true, y_pred, labels=class_labels, average=None, zero_division=0)
    per_class_rec = recall_score(y_true, y_pred, labels=class_labels, average=None, zero_division=0)

    class_metrics = {}
    for i, c in enumerate(class_labels):
        class_metrics[c] = {
            "f1": round(float(per_class_f1[i]), 4),
            "precision": round(float(per_class_prec[i]), 4),
            "recall": round(float(per_class_rec[i]), 4),
            "support": int(np.sum(y_true == c)),
        }

    # Security-specific critical errors:
    # 1. False GOOD on POOR (catastrophic security risk: telling a broken site it is safe)
    # 2. False POOR on GOOD (unnecessary alert fatigue)
    false_good_on_poor = 0
    false_poor_on_good = 0
    total_poor = int(np.sum(y_true == "POOR"))
    total_good = int(np.sum(y_true == "GOOD"))

    for yt, yp in zip(y_true, y_pred):
        if yt == "POOR" and yp == "GOOD":
            false_good_on_poor += 1
        elif yt == "GOOD" and yp == "POOR":
            false_poor_on_good += 1

    crit_risk_rate = round(false_good_on_poor / max(1, total_poor) * 100, 2)
    over_conservative_rate = round(false_poor_on_good / max(1, total_good) * 100, 2)

    metrics = {
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "per_class": class_metrics,
        "confusion_matrix": {
            "labels": class_labels,
            "matrix": cm.tolist(),
        },
        "security_penalties": {
            "false_good_on_poor_count": false_good_on_poor,
            "false_good_on_poor_rate_pct": crit_risk_rate,
            "false_poor_on_good_count": false_poor_on_good,
            "false_poor_on_good_rate_pct": over_conservative_rate,
        },
    }

    if y_proba is not None:
        try:
            # Multi-class ROC AUC
            roc_auc = float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro"))
            metrics["macro_roc_auc"] = round(roc_auc, 4)
        except Exception:
            metrics["macro_roc_auc"] = None

        try:
            loss = float(log_loss(y_true, y_proba, labels=class_labels))
            metrics["log_loss"] = round(loss, 4)
        except Exception:
            metrics["log_loss"] = None

    return metrics

