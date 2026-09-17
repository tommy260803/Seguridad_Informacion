import numpy as np

from phishguard_ml.evaluation import (
    classification_metrics,
    expected_calibration_error,
    select_f1_threshold,
)


def test_metrics_for_perfect_predictions() -> None:
    truth = np.asarray([0, 0, 1, 1], dtype=np.int8)
    probability = np.asarray([0.05, 0.1, 0.9, 0.95])

    metrics = classification_metrics(truth, probability, threshold=0.5, ece_bins=4)

    assert metrics["accuracy"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["confusion_matrix"] == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}


def test_threshold_selection_and_ece_are_deterministic() -> None:
    truth = np.asarray([0, 0, 1, 1], dtype=np.int8)
    probability = np.asarray([0.1, 0.4, 0.45, 0.9])

    selected = select_f1_threshold(truth, probability)

    assert selected["threshold"] == 0.45
    assert selected["f1"] == 1.0
    assert expected_calibration_error(truth, probability, bins=5) >= 0.0
