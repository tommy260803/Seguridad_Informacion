from __future__ import annotations

import numpy as np


def robustness_metrics(
    y_true: np.ndarray,
    clean_probability: np.ndarray,
    perturbed_probability: np.ndarray,
    threshold: float = 0.5,
) -> dict[str, float]:
    if clean_probability.shape != perturbed_probability.shape or len(y_true) != len(clean_probability):
        raise ValueError("robustness arrays must have equal shape")
    clean = clean_probability >= threshold
    perturbed = perturbed_probability >= threshold

    pos_mask = y_true == 1
    clean_recall = float(clean[pos_mask].mean()) if pos_mask.any() else 0.0
    perturbed_recall = float(perturbed[pos_mask].mean()) if pos_mask.any() else 0.0
    detected_clean_mask = pos_mask & clean
    asr = (
        float((~perturbed[detected_clean_mask]).mean())
        if detected_clean_mask.any()
        else 0.0
    )

    return {
        "samples": float(len(y_true)),
        "phishing_samples": float(pos_mask.sum()),
        "clean_error_rate": float((clean != y_true).mean()),
        "perturbed_error_rate": float((perturbed != y_true).mean()),
        "error_rate_delta": float((perturbed != y_true).mean() - (clean != y_true).mean()),
        "clean_recall": clean_recall,
        "perturbed_recall": perturbed_recall,
        "recall_drop_abs": clean_recall - perturbed_recall,
        "recall_drop_rel_pct": ((clean_recall - perturbed_recall) / clean_recall * 100.0) if clean_recall > 0 else 0.0,
        "attack_success_rate": asr,
        "mean_probability_shift": float(np.mean(np.abs(perturbed_probability - clean_probability))),
        "label_flip_rate": float((clean != perturbed).mean()),
    }
