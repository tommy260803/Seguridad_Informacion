import numpy as np
import pytest

from phishguard_ml.evaluation import coverage_risk_curve, select_abstention_threshold


def test_coverage_risk_curve_reports_selective_metrics() -> None:
    curve = coverage_risk_curve(np.array([0, 1, 1, 0]), np.array([0.05, 0.95, 0.52, 0.48]))
    assert curve[0]["coverage"] == 1.0
    assert all("abstention_rate" in row for row in curve)


def test_abstention_threshold_is_selected_on_constraints() -> None:
    selected = select_abstention_threshold(np.array([0, 1, 1, 0]), np.array([0.05, 0.95, 0.52, 0.48]), maximum_risk=0.0, minimum_coverage=0.5)
    assert selected["coverage"] >= 0.5
    assert selected["selective_risk"] == 0.0


def test_abstention_rejects_invalid_constraints() -> None:
    with pytest.raises(ValueError):
        select_abstention_threshold(np.array([0, 1]), np.array([0.2, 0.8]), maximum_risk=2.0)
