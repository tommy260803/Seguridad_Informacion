from __future__ import annotations

import numpy as np


def robustness_metrics(y_true: np.ndarray, clean_probability: np.ndarray, perturbed_probability: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    if clean_probability.shape != perturbed_probability.shape or len(y_true) != len(clean_probability):
        raise ValueError("robustness arrays must have equal shape")
    clean = clean_probability >= threshold
    perturbed = perturbed_probability >= threshold
    return {
        "samples": float(len(y_true)),
        "clean_error_rate": float((clean != y_true).mean()),
        "perturbed_error_rate": float((perturbed != y_true).mean()),
        "error_rate_delta": float((perturbed != y_true).mean() - (clean != y_true).mean()),
        "mean_probability_shift": float(np.mean(np.abs(perturbed_probability - clean_probability))),
        "label_flip_rate": float((clean != perturbed).mean()),
    }
