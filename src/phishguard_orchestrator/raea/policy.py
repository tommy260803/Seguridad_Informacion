from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from phishguard_orchestrator.raea.models import (
    Action,
    DecisionState,
    RAEAConfig,
    TransitionLog,
)
from phishguard_orchestrator.raea.risk import RiskEstimator
from phishguard_orchestrator.raea.availability import AvailabilityEstimator
from phishguard_orchestrator.raea.cost import AcquisitionCostEstimator


class AbstentionHandler:
    """Gestiona las políticas operativas sobre las abstenciones."""

    def __init__(self, mode: str = "uncertain"):
        self.mode = mode

    def resolve_decision(self, final_prob: float) -> str:
        if self.mode == "fail_closed":
            return "phishing"
        elif self.mode == "fail_open":
            return "legitimate"
        else:
            return "uncertain"


class ActionSelector:
    """Motor de cálculo y selección óptima de acciones para RAEA-Phish."""

    def __init__(
        self,
        config: RAEAConfig | None = None,
        risk_estimator: RiskEstimator | None = None,
        availability_estimator: AvailabilityEstimator | None = None,
        cost_estimator: AcquisitionCostEstimator | None = None,
    ):
        self.config = config or RAEAConfig()
        self.risk_estimator = risk_estimator or RiskEstimator(self.config)
        self.availability_estimator = availability_estimator or AvailabilityEstimator(config=self.config)
        self.cost_estimator = cost_estimator or AcquisitionCostEstimator(config=self.config)

    def select_action(self, state: DecisionState) -> Tuple[Action, TransitionLog]:
        # 1. Evaluar riesgos terminales
        r_phish, r_benign, r_abstain, guard_passed = self.risk_estimator.evaluate_terminal_risks(state)

        q_values: Dict[str, float] = {
            Action.STOP_PHISHING.value: r_phish,
            Action.STOP_BENIGN.value: r_benign,
            Action.ABSTAIN.value: r_abstain,
        }

        # 2. Determinar siguiente modalidad permitida según orden de dependencia
        next_modality: Optional[str] = None
        action_acq: Optional[Action] = None

        if "network" not in state.consulted_modalities:
            next_modality = "network"
            action_acq = Action.ACQUIRE_NETWORK
        elif "html" not in state.consulted_modalities:
            next_modality = "html"
            action_acq = Action.ACQUIRE_HTML
        elif "visual" not in state.consulted_modalities:
            next_modality = "visual"
            action_acq = Action.ACQUIRE_VISUAL

        est_avail: Optional[float] = None
        est_cost: Optional[float] = None

        # 3. Evaluar valor Q de la acción de adquisición si es válida y hay presupuesto
        if next_modality and action_acq:
            est_avail = self.availability_estimator.predict_availability(next_modality, state.x0_features)
            est_cost = self.cost_estimator.estimate_cost(next_modality, est_avail)

            budget_ok = est_cost <= state.remaining_budget
            avail_ok = est_avail >= self.config.tau_avail_min or not self.config.enable_availability

            if budget_ok and avail_ok:
                r_term_current = min(r_phish, r_benign, r_abstain)
                r_post_esp = self.risk_estimator.estimate_posterior_risk(
                    state.current_probability,
                    est_avail,
                    next_modality,
                    current_terminal_risk=r_term_current,
                )
                q_acq = r_post_esp + self.config.lambda_cost * est_cost
                q_values[action_acq.value] = q_acq
            else:
                q_values[action_acq.value] = float("inf")

        # 4. Seleccionar acción que minimiza Q
        best_action_str = min(q_values, key=q_values.get)
        best_action = Action(best_action_str)

        if best_action == Action.STOP_PHISHING:
            reason = f"bayes_risk_phishing_minimal (p={state.current_probability:.4f})"
        elif best_action == Action.STOP_BENIGN:
            reason = f"bayes_risk_benign_minimal (p={state.current_probability:.4f}, guard_passed={guard_passed})"
        elif best_action == Action.ABSTAIN:
            reason = f"uncertainty_exceeds_threshold_budget_exhausted (p={state.current_probability:.4f})"
        else:
            reason = f"expected_acquisition_value_optimal ({next_modality}, avail={est_avail:.2f}, cost={est_cost:.2f})"

        trans = TransitionLog(
            step=state.step,
            action=best_action,
            probability_phishing=state.current_probability,
            risk_phishing=r_phish,
            risk_benign=r_benign,
            risk_abstain=r_abstain,
            q_values=q_values,
            estimated_availability=est_avail,
            estimated_cost=est_cost,
            reason=reason,
        )
        return best_action, trans


class RiskAvailabilityAwarePolicy:
    """Implementa la política completa RAEA-Phish."""

    def __init__(self, config: RAEAConfig | None = None):
        self.config = config or RAEAConfig()
        self.action_selector = ActionSelector(self.config)
        self.abstention_handler = AbstentionHandler()

    def get_config(self) -> RAEAConfig:
        return self.config
