"""Evaluation Metrics and Scientific Validation for SafeContain AI ML Pipeline.

Computes comprehensive binary classification and unsupervised anomaly detection
metrics, confusion matrices, and cross-validation score distributions.
"""

from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
)


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    """Computes comprehensive binary classification evaluation metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0

    metrics: Dict[str, Any] = {
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "specificity": round(spec, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "total_samples": int(len(y_true)),
        "positive_samples": int(np.sum(y_true)),
        "negative_samples": int(len(y_true) - np.sum(y_true)),
    }

    if y_prob is not None:
        try:
            # If y_prob is 2D (proba for both classes), take column 1
            if len(y_prob.shape) > 1 and y_prob.shape[1] == 2:
                prob_pos = y_prob[:, 1]
            else:
                prob_pos = y_prob.ravel()

            # Ensure at least 1 instance of each class exists in y_true for AUC
            if len(np.unique(y_true)) > 1:
                metrics["roc_auc"] = round(float(roc_auc_score(y_true, prob_pos)), 4)
                metrics["average_precision"] = round(float(average_precision_score(y_true, prob_pos)), 4)
            else:
                metrics["roc_auc"] = None
                metrics["average_precision"] = None

            metrics["brier_score"] = round(float(brier_score_loss(y_true, prob_pos)), 4)
        except Exception as e:
            metrics["auc_error"] = str(e)

    return metrics


def aggregate_cv_metrics(cv_results: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregates multi-fold cross validation score arrays into mean and standard deviation."""
    aggregated: Dict[str, Any] = {}
    for metric_name, scores in cv_results.items():
        if metric_name.startswith("test_") or metric_name.startswith("train_"):
            scores_arr = np.array(scores)
            clean_name = metric_name.replace("test_", "").replace("train_", "")
            prefix = "train_" if metric_name.startswith("train_") else ""
            aggregated[f"{prefix}{clean_name}_mean"] = round(float(np.mean(scores_arr)), 4)
            aggregated[f"{prefix}{clean_name}_std"] = round(float(np.std(scores_arr)), 4)
            aggregated[f"{prefix}{clean_name}_folds"] = [round(float(s), 4) for s in scores_arr]
    return aggregated


def compute_anomaly_metrics(
    scores: np.ndarray,
    outliers: np.ndarray,
    node_ids: List[str],
) -> Dict[str, Any]:
    """Analyzes Isolation Forest anomaly score distributions and identifies top outliers."""
    outlier_mask = outliers == -1
    anomaly_count = int(np.sum(outlier_mask))
    inlier_count = int(len(outliers) - anomaly_count)
    contamination = round(float(anomaly_count / len(outliers)), 4) if len(outliers) > 0 else 0.0

    score_stats = {
        "mean": round(float(np.mean(scores)), 4),
        "std": round(float(np.std(scores)), 4),
        "min": round(float(np.min(scores)), 4),
        "25th_percentile": round(float(np.percentile(scores, 25)), 4),
        "median": round(float(np.median(scores)), 4),
        "75th_percentile": round(float(np.percentile(scores, 75)), 4),
        "max": round(float(np.max(scores)), 4),
    }

    # Rank nodes by anomaly score (lowest score = most anomalous)
    ranked_indices = np.argsort(scores)
    top_outliers = []
    for idx in ranked_indices[:min(15, len(ranked_indices))]:
        top_outliers.append({
            "node_id": node_ids[idx],
            "anomaly_score": round(float(scores[idx]), 4),
            "is_anomaly": bool(outliers[idx] == -1),
        })

    return {
        "total_entities_evaluated": len(scores),
        "anomalies_detected": anomaly_count,
        "inliers_count": inlier_count,
        "empirical_contamination_rate": contamination,
        "anomaly_score_distribution": score_stats,
        "top_anomalous_entities": top_outliers,
    }
