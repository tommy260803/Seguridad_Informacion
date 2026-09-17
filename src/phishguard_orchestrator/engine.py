from __future__ import annotations

from dataclasses import replace
from math import log2

from phishguard_orchestrator.models import AdaptivePolicy, OrchestrationResult, Transition


class OrchestratorError(ValueError):
    pass


def _uncertainty(probability: float) -> float:
    if not 0.0 <= probability <= 1.0:
        raise OrchestratorError("probability_phishing must be between 0 and 1")
    if probability in (0.0, 1.0):
        return 0.0
    entropy = -(probability * log2(probability) + (1 - probability) * log2(1 - probability))
    return float(entropy)


def decide_next(
    probability_phishing: float,
    consulted: tuple[str, ...],
    policy: AdaptivePolicy,
    *,
    step: int = 0,
) -> tuple[str, str, float, float]:
    uncertainty = _uncertainty(probability_phishing)
    confidence = 1.0 - uncertainty
    if confidence >= policy.minimum_confidence or uncertainty <= policy.uncertainty_threshold:
        return "decide", "evidence_sufficient", confidence, uncertainty
    for modality in ("infrastructure", "content", "visual"):
        if modality not in consulted and policy.costs.get(modality, 0.0) <= policy.budget:
            return modality, "uncertainty_above_threshold", confidence, uncertainty
    return "abstain", "budget_exhausted_or_no_evidence", confidence, uncertainty


def run_adaptive(
    url_probability: float,
    modality_probabilities: dict[str, float],
    policy: AdaptivePolicy | None = None,
) -> OrchestrationResult:
    policy = policy or AdaptivePolicy()
    if policy.budget < 0 or any(cost < 0 for cost in policy.costs.values()):
        raise OrchestratorError("budget and modality costs must be non-negative")
    probability = url_probability
    consulted: list[str] = ["url"]
    transitions: list[Transition] = []
    spent = 0.0
    step = 0
    while True:
        action, reason, confidence, uncertainty = decide_next(probability, tuple(consulted), replace(policy, budget=policy.budget - spent), step=step)
        transitions.append(Transition(step, "decision" if action in {"decide", "abstain"} else "acquire", None if action in {"decide", "abstain"} else action, reason, probability, uncertainty, policy.budget - spent))
        if action in {"decide", "abstain"}:
            decision = "phishing" if action == "decide" and probability >= 0.5 else "legitimate" if action == "decide" else "uncertain"
            return OrchestrationResult(decision, probability, confidence, uncertainty, tuple(consulted), tuple(transitions), spent)
        cost = policy.costs.get(action, 0.0)
        if action not in modality_probabilities:
            raise OrchestratorError(f"Missing probability for modality: {action}")
        spent += cost
        probability = float(modality_probabilities[action])
        consulted.append(action)
        step += 1
