from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def shannon_entropy(probability: np.ndarray) -> np.ndarray:
    """Compute binary Shannon entropy H(p) in [0, 1] safely for an array of probabilities."""
    p = np.clip(np.asarray(probability, dtype=np.float64), 1e-12, 1.0 - 1e-12)
    h = -(p * np.log2(p) + (1.0 - p) * np.log2(1.0 - p))
    h = np.where((probability <= 0.0) | (probability >= 1.0), 0.0, h)
    return np.clip(h, 0.0, 1.0)


def shannon_confidence(probability: np.ndarray) -> np.ndarray:
    """Compute confidence C(p) = 1 - H(p) in [0, 1]."""
    return 1.0 - shannon_entropy(probability)


def expected_calibration_error(y_true: np.ndarray, probability: np.ndarray, bins: int) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(y_true)
    if total == 0:
        return 0.0
    error = 0.0
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        mask = (probability >= lower) & (probability < upper if index < bins - 1 else probability <= upper)
        count = int(mask.sum())
        if not count:
            continue
        confidence = float(probability[mask].mean())
        observed = float(y_true[mask].mean())
        error += (count / total) * abs(confidence - observed)
    return float(error)


def select_f1_threshold(y_true: np.ndarray, probability: np.ndarray) -> dict[str, float]:
    precision, recall, thresholds = precision_recall_curve(y_true, probability)
    if len(thresholds) == 0:
        return {"threshold": 0.5, "f1": 0.0, "precision": 0.0, "recall": 0.0}
    f1 = np.divide(
        2 * precision[:-1] * recall[:-1],
        precision[:-1] + recall[:-1],
        out=np.zeros_like(thresholds),
        where=(precision[:-1] + recall[:-1]) > 0,
    )
    best = max(
        range(len(thresholds)),
        key=lambda index: (float(f1[index]), float(recall[index]), -float(thresholds[index])),
    )
    return {
        "threshold": float(thresholds[best]),
        "f1": float(f1[best]),
        "precision": float(precision[best]),
        "recall": float(recall[best]),
    }


def select_fpr_threshold(
    y_true: np.ndarray, probability: np.ndarray, max_fpr: float = 0.01
) -> dict[str, float]:
    """Select threshold maximizing recall subject to FPR <= max_fpr on validation."""
    fpr, tpr, thresholds = roc_curve(y_true, probability)
    valid = [i for i in range(len(thresholds)) if fpr[i] <= max_fpr and np.isfinite(thresholds[i])]
    if not valid:
        return {"threshold": 0.9, "fpr": 0.0, "recall": 0.0}
    best = max(valid, key=lambda i: (float(tpr[i]), -float(fpr[i])))
    return {
        "threshold": float(thresholds[best]),
        "fpr": float(fpr[best]),
        "recall": float(tpr[best]),
    }


def classification_metrics(
    y_true: np.ndarray,
    probability: np.ndarray,
    threshold: float,
    ece_bins: int,
) -> dict[str, Any]:
    prediction = (probability >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_true, prediction, labels=[0, 1]).ravel()
    specificity = tn / (tn + fp) if tn + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = precision_score(y_true, prediction, zero_division=0)
    recall = recall_score(y_true, prediction, zero_division=0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    roc_val = float(roc_auc_score(y_true, probability)) if len(np.unique(y_true)) > 1 else 0.0
    pr_val = float(average_precision_score(y_true, probability)) if len(np.unique(y_true)) > 1 else 0.0
    return {
        "samples": int(len(y_true)),
        "threshold": float(threshold),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "accuracy": float(accuracy_score(y_true, prediction)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "specificity": float(specificity),
        "false_positive_rate": float(fpr),
        "roc_auc": roc_val,
        "pr_auc": pr_val,
        "brier_score": float(brier_score_loss(y_true, probability)),
        "expected_calibration_error": expected_calibration_error(y_true, probability, ece_bins),
    }


def coverage_risk_curve(
    y_true: np.ndarray,
    probability: np.ndarray,
    thresholds: list[float] | None = None,
    *,
    metric: str = "linear",
    decision_threshold: float = 0.5,
) -> list[dict[str, float]]:
    """Return selective risk as low-confidence predictions are abstained."""
    if len(y_true) != len(probability) or len(y_true) == 0:
        raise ValueError("y_true and probability must be non-empty and have equal length")
    if not np.isfinite(probability).all():
        raise ValueError("probability contains non-finite values")
    thresholds = thresholds or [round(index / 20, 2) for index in range(0, 21)]
    if metric == "entropy":
        confidence = shannon_confidence(probability)
    elif metric == "linear":
        confidence = np.abs(probability - 0.5) * 2.0
    else:
        raise ValueError(f"Unsupported confidence metric: {metric}")

    curve = []
    for threshold in sorted(set(thresholds)):
        selected = confidence >= threshold
        coverage = float(selected.mean())
        errors = (
            float(((probability[selected] >= decision_threshold).astype(np.int8) != y_true[selected]).mean())
            if selected.any()
            else 0.0
        )
        curve.append(
            {
                "confidence_threshold": float(threshold),
                "entropy_threshold": float(1.0 - threshold),
                "coverage": coverage,
                "abstention_rate": 1.0 - coverage,
                "selective_risk": errors,
            }
        )
    return curve


def select_abstention_threshold(
    y_true: np.ndarray,
    probability: np.ndarray,
    *,
    maximum_risk: float,
    minimum_coverage: float = 0.0,
    metric: str = "linear",
    decision_threshold: float = 0.5,
) -> dict[str, float]:
    """Choose the least restrictive confidence threshold meeting validation goals."""
    if not 0.0 <= maximum_risk <= 1.0 or not 0.0 <= minimum_coverage <= 1.0:
        raise ValueError("risk and coverage constraints must be between 0 and 1")
    candidates = [
        row
        for row in coverage_risk_curve(
            y_true, probability, metric=metric, decision_threshold=decision_threshold
        )
        if row["selective_risk"] <= maximum_risk and row["coverage"] >= minimum_coverage
    ]
    if not candidates:
        return {
            "confidence_threshold": 1.0,
            "entropy_threshold": 0.0,
            "coverage": 0.0,
            "abstention_rate": 1.0,
            "selective_risk": 0.0,
        }
    return min(candidates, key=lambda row: (row["confidence_threshold"], -row["coverage"]))
