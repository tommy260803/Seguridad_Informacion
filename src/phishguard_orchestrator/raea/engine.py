from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from phishguard_orchestrator.raea.models import (
    Action,
    AcquisitionStatus,
    DecisionState,
    RAEAConfig,
    RAEAExecutionResult,
    TransitionLog,
)
from phishguard_orchestrator.raea.policy import (
    ActionSelector,
    RiskAvailabilityAwarePolicy,
)
from phishguard_orchestrator.raea.adapter import EvidenceAcquisitionAdapter
from phishguard_orchestrator.raea.logger import DecisionLogger


def evaluate_lexical_risk(x0: Dict[str, float]) -> bool:
    """Evalúa si la URL posee factores intrínsecos de alto riesgo de evasión léxica."""
    if bool(x0.get("has_ip_host", 0.0)):
        return True
    if bool(x0.get("is_ip_host", 0.0)):
        return True
    if bool(x0.get("is_shortener", 0.0)):
        return True
    if bool(x0.get("has_punycode", 0.0)) or bool(x0.get("is_idn_punycode", 0.0)):
        return True
    # Subdominios excesivos fuera de listas de reputación
    n_labels = float(x0.get("host_label_count", 2.0))
    in_tranco = bool(x0.get("in_tranco_top1m", 0.0))
    if n_labels >= 4.0 and not in_tranco:
        return True
    return False


def decide_next_raea(
    probability_phishing: float,
    consulted: Tuple[str, ...],
    x0_features: Dict[str, float],
    config: RAEAConfig | None = None,
    *,
    step: int = 0,
    remaining_budget: float = 3.0,
    spent_cost: float = 0.0,
) -> Tuple[str, str, float, float]:
    """
    Función de decisión paso a paso compatible con la interfaz del worker de PhishPe.
    Retorna (action_name, reason, confidence, uncertainty).
    action_name: "decide", "abstain", "infrastructure", "content", "visual"
    """
    cfg = config or RAEAConfig()
    policy = RiskAvailabilityAwarePolicy(cfg)
    has_lex_risk = evaluate_lexical_risk(x0_features)

    # Normalizar nombres de modalidades consultadas (mapear infrastructure -> network, content -> html)
    normalized_consulted = []
    for m in consulted:
        if m in ("infrastructure", "network"):
            normalized_consulted.append("network")
        elif m in ("content", "html"):
            normalized_consulted.append("html")
        else:
            normalized_consulted.append(m)

    state = DecisionState(
        step=step,
        url="",
        x0_features=x0_features,
        consulted_modalities=tuple(normalized_consulted),
        acquisition_statuses={m: "success" for m in normalized_consulted},
        current_probability=probability_phishing,
        remaining_budget=remaining_budget,
        spent_cost=spent_cost,
        has_lexical_risk=has_lex_risk,
    )

    action, trans = policy.action_selector.select_action(state)
    confidence = float(max(probability_phishing, 1.0 - probability_phishing))
    uncertainty = float(1.0 - confidence)

    if action in (Action.STOP_PHISHING, Action.STOP_BENIGN):
        return "decide", trans.reason, confidence, uncertainty
    elif action == Action.ABSTAIN:
        return "abstain", trans.reason, confidence, uncertainty
    elif action == Action.ACQUIRE_NETWORK:
        return "infrastructure", trans.reason, confidence, uncertainty
    elif action == Action.ACQUIRE_HTML:
        return "content", trans.reason, confidence, uncertainty
    elif action == Action.ACQUIRE_VISUAL:
        return "visual", trans.reason, confidence, uncertainty
    else:
        return "decide", trans.reason, confidence, uncertainty


def run_raea(
    url: str,
    x0_features: Dict[str, float],
    initial_probability: float,
    modality_probabilities: Dict[str, float] | None = None,
    config: RAEAConfig | None = None,
    offline_data: Dict[str, Any] | None = None,
    logger: DecisionLogger | None = None,
) -> RAEAExecutionResult:
    """
    Ejecuta el ciclo de inferencia adaptativa RAEA-Phish sobre una URL.
    """
    cfg = config or RAEAConfig()
    policy = RiskAvailabilityAwarePolicy(cfg)
    adapter = EvidenceAcquisitionAdapter(offline_data=offline_data)

    has_lex_risk = evaluate_lexical_risk(x0_features)
    consulted: List[str] = ["url"]
    acquisition_statuses: Dict[str, str] = {"url": "success"}
    transitions: List[TransitionLog] = []

    current_p = float(max(0.0, min(1.0, initial_probability)))
    remaining_budget = float(cfg.initial_budget)
    spent_cost = 0.0
    step = 0

    while True:
        state = DecisionState(
            step=step,
            url=url,
            x0_features=x0_features,
            consulted_modalities=tuple(consulted),
            acquisition_statuses=dict(acquisition_statuses),
            current_probability=current_p,
            remaining_budget=remaining_budget,
            spent_cost=spent_cost,
            has_lexical_risk=has_lex_risk,
        )

        action, trans = policy.action_selector.select_action(state)
        transitions.append(trans)

        if action == Action.STOP_PHISHING:
            res = RAEAExecutionResult(
                decision="phishing",
                probability_phishing=current_p,
                modalities_consulted=tuple(consulted),
                total_cost=spent_cost,
                abstained=False,
                transitions=tuple(transitions),
            )
            if logger:
                logger.log_execution(url, res)
            return res

        elif action == Action.STOP_BENIGN:
            res = RAEAExecutionResult(
                decision="legitimate",
                probability_phishing=current_p,
                modalities_consulted=tuple(consulted),
                total_cost=spent_cost,
                abstained=False,
                transitions=tuple(transitions),
            )
            if logger:
                logger.log_execution(url, res)
            return res

        elif action == Action.ABSTAIN:
            dec_label = policy.abstention_handler.resolve_decision(current_p)
            res = RAEAExecutionResult(
                decision=dec_label,
                probability_phishing=current_p,
                modalities_consulted=tuple(consulted),
                total_cost=spent_cost,
                abstained=True,
                transitions=tuple(transitions),
            )
            if logger:
                logger.log_execution(url, res)
            return res

        # Acciones de Adquisición
        modality_to_acquire = (
            "network" if action == Action.ACQUIRE_NETWORK
            else "html" if action == Action.ACQUIRE_HTML
            else "visual"
        )

        # Adquirir
        if offline_data:
            st, feats, lat, p_new = adapter.acquire_modality(modality_to_acquire, url)
        elif modality_probabilities and modality_to_acquire in modality_probabilities:
            st = AcquisitionStatus.SUCCESS
            p_new = float(modality_probabilities[modality_to_acquire])
            lat = 200.0 if modality_to_acquire == "network" else 500.0 if modality_to_acquire == "html" else 1500.0
        else:
            st = AcquisitionStatus.ERROR
            p_new = current_p
            lat = 100.0

        cost_inc = trans.estimated_cost or 0.5
        spent_cost += cost_inc
        remaining_budget = max(0.0, remaining_budget - cost_inc)

        consulted.append(modality_to_acquire)
        acquisition_statuses[modality_to_acquire] = st.value
        current_p = p_new
        step += 1
