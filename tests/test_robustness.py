import numpy as np
import pytest

from phishguard_robustness.metrics import robustness_metrics
from phishguard_robustness.perturbations import generate_suite, perturb_url


def test_perturbation_suite_is_deterministic_and_local() -> None:
    first = generate_suite("https://secure.example/login", kind="url", seed=7)
    second = generate_suite("https://secure.example/login", kind="url", seed=7)
    assert first == second
    assert all(item.original in "https://secure.example/login" or item.perturbed for item in first)
    assert perturb_url("https://example.test", "path_noise").perturbed.startswith("https://example.test/")


def test_robustness_metrics_reports_degradation() -> None:
    result = robustness_metrics(np.array([0, 1, 1]), np.array([0.1, 0.9, 0.8]), np.array([0.6, 0.9, 0.2]))
    assert result["label_flip_rate"] > 0
    assert result["error_rate_delta"] > 0


def test_unsupported_perturbation_is_rejected() -> None:
    with pytest.raises(ValueError):
        perturb_url("https://example.test", "redirect_attack")
