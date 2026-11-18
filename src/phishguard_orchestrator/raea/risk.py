from __future__ import annotations

from typing import Tuple
from phishguard_orchestrator.raea.models import DecisionState, RAEAConfig


class RiskEstimator:
    """Calcula los riesgos condicionales de Bayes para las decisiones terminales."""

    def __init__(self, config: RAEAConfig | None = None):
        self.config = config or RAEAConfig()

    def evaluate_terminal_risks(
        self,
        state: DecisionState,
    ) -> Tuple[float, float, float, bool]:
        """
        Retorna (risk_phish, risk_benign, risk_abstain, benign_guard_passed).
        """
        p = max(0.0, min(1.0, state.current_probability))
        c_fp = self.config.c_fp
        gamma = self.config.gamma if self.config.enable_asymmetric_cost else 1.0
        c_fn = gamma * c_fp
        c_abst = self.config.cost_abstain if self.config.enable_abstention else float("inf")

        # Riesgo de decir Phishing (error si es legítimo)
        risk_phish = c_fp * (1.0 - p)

        # Guarda contra salida benigna prematura
        benign_guard_passed = True
        if self.config.enforce_benign_guard and state.step == 0:
            if p > self.config.p_safe or state.has_lexical_risk:
                benign_guard_passed = False

        if not benign_guard_passed:
            risk_benign = float("inf")
        else:
            risk_benign = c_fn * p

        risk_abstain = c_abst
        return risk_phish, risk_benign, risk_abstain, benign_guard_passed

    def estimate_posterior_risk(
        self,
        current_p: float,
        expected_avail: float,
        modality: str,
        current_terminal_risk: float | None = None,
    ) -> float:
        """
        Estima el riesgo posterior esperado E[R*(S_t+1)] si se adquiere la modalidad.
        """
        gamma = self.config.gamma if self.config.enable_asymmetric_cost else 1.0
        c_fp = self.config.c_fp
        c_fn = gamma * c_fp
        c_abst = self.config.cost_abstain if self.config.enable_abstention else float("inf")

        base_risk = current_terminal_risk if current_terminal_risk is not None else min(c_fp * (1.0 - current_p), c_fn * current_p, c_abst)

        if not self.config.enable_information_value:
            # Ablación A4: sin beneficio informativo esperado, la adquisición no reduce
            # el riesgo terminal esperado. (Antes se devolvía current_p, una probabilidad
            # en unidades distintas a las de riesgo: error dimensional.)
            return float(base_risk)

        reduction_factors = {
            "network": 0.25,
            "html": 0.20,
            "visual": 0.15,
        }
        factor = reduction_factors.get(modality, 0.25)

        # Si tiene éxito, la evidencia multimodal reduce fuertemente el riesgo
        r_succ = base_risk * factor
        # Si falla, el riesgo terminal no empeora más allá de la abstención / mejor opción actual
        r_fail = base_risk

        expected_risk = expected_avail * r_succ + (1.0 - expected_avail) * r_fail
        return float(expected_risk)
