import pytest

from phishguard_orchestrator.engine import OrchestratorError, run_adaptive
from phishguard_orchestrator.models import AdaptivePolicy


def test_adaptive_policy_stops_when_url_evidence_is_confident() -> None:
    result = run_adaptive(0.98, {}, AdaptivePolicy())
    assert result.decision == "phishing"
    assert result.modalities_consulted == ("url",)
    assert result.cost == 0.0


def test_adaptive_policy_acquires_progressively_and_records_transitions() -> None:
    result = run_adaptive(0.5, {"infrastructure": 0.52, "content": 0.99, "visual": 0.9}, AdaptivePolicy(budget=2.0))
    assert result.decision == "phishing"
    assert result.modalities_consulted == ("url", "infrastructure", "content")
    assert result.cost == 2.0
    assert len(result.transitions) == 3


def test_adaptive_policy_abstains_when_budget_is_exhausted() -> None:
    result = run_adaptive(0.5, {"infrastructure": 0.5}, AdaptivePolicy(budget=0.0))
    assert result.decision == "uncertain"
    assert result.modalities_consulted == ("url",)


def test_adaptive_policy_rejects_invalid_probability() -> None:
    with pytest.raises(OrchestratorError):
        run_adaptive(1.2, {})
