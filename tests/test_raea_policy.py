import pytest
from phishguard_orchestrator.raea.models import (
    Action,
    DecisionState,
    RAEAConfig,
    RAEAExecutionResult,
)
from phishguard_orchestrator.raea.risk import RiskEstimator
from phishguard_orchestrator.raea.availability import AvailabilityEstimator
from phishguard_orchestrator.raea.cost import AcquisitionCostEstimator
from phishguard_orchestrator.raea.policy import (
    ActionSelector,
    RiskAvailabilityAwarePolicy,
)
from phishguard_orchestrator.raea.engine import (
    decide_next_raea,
    evaluate_lexical_risk,
    run_raea,
)
from phishguard_orchestrator.raea.logger import DecisionLogger


def test_lexical_risk_detection():
    # Caso 1: host por IP
    assert evaluate_lexical_risk({"has_ip_host": 1.0}) is True
    # Caso 2: acortador
    assert evaluate_lexical_risk({"is_shortener": 1.0}) is True
    # Caso 3: punycode
    assert evaluate_lexical_risk({"has_punycode": 1.0}) is True
    # Caso 4: subdominios excesivos fuera de tranco
    assert evaluate_lexical_risk({"host_label_count": 5.0, "in_tranco_top1m": 0.0}) is True
    # Caso 5: dominio limpio en tranco
    assert evaluate_lexical_risk({"host_label_count": 2.0, "in_tranco_top1m": 1.0}) is False


def test_benign_guard_blocks_premature_exit():
    cfg = RAEAConfig(p_safe=0.02, gamma=15.0)
    risk_est = RiskEstimator(cfg)

    # Estado con p0 muy baja (0.01) pero con riesgo léxico (IP host)
    state = DecisionState(
        step=0,
        url="http://192.168.1.1/login",
        x0_features={"has_ip_host": 1.0},
        consulted_modalities=("url",),
        acquisition_statuses={"url": "success"},
        current_probability=0.01,
        remaining_budget=3.0,
        spent_cost=0.0,
        has_lexical_risk=True,
    )
    r_phish, r_benign, r_abstain, guard_passed = risk_est.evaluate_terminal_risks(state)

    assert guard_passed is False
    assert r_benign == float("inf")  # Acción prohibida por la guarda


def test_benign_guard_permits_safe_url():
    cfg = RAEAConfig(p_safe=0.02, gamma=15.0)
    risk_est = RiskEstimator(cfg)

    state = DecisionState(
        step=0,
        url="https://google.com",
        x0_features={"has_ip_host": 0.0, "is_shortener": 0.0, "has_punycode": 0.0},
        consulted_modalities=("url",),
        acquisition_statuses={"url": "success"},
        current_probability=0.005,
        remaining_budget=3.0,
        spent_cost=0.0,
        has_lexical_risk=False,
    )
    r_phish, r_benign, r_abstain, guard_passed = risk_est.evaluate_terminal_risks(state)

    assert guard_passed is True
    assert r_benign < float("inf")
    assert r_benign == pytest.approx(15.0 * 0.005, abs=1e-5)


def test_high_phishing_probability_triggers_stop_phishing():
    cfg = RAEAConfig(gamma=15.0)
    selector = ActionSelector(cfg)

    state = DecisionState(
        step=0,
        url="http://phishing-site.tk/verify",
        x0_features={},
        consulted_modalities=("url",),
        acquisition_statuses={"url": "success"},
        current_probability=0.98,
        remaining_budget=3.0,
        spent_cost=0.0,
        has_lexical_risk=True,
    )
    action, trans = selector.select_action(state)
    assert action == Action.STOP_PHISHING


def test_uncertain_triggers_acquisition_when_available():
    cfg = RAEAConfig(gamma=15.0, initial_budget=3.0)
    selector = ActionSelector(cfg)

    state = DecisionState(
        step=0,
        url="http://suspicious-unknown-domain.com/auth",
        x0_features={"uses_https": 1.0, "p_m0": 0.50},
        consulted_modalities=("url",),
        acquisition_statuses={"url": "success"},
        current_probability=0.50,
        remaining_budget=3.0,
        spent_cost=0.0,
        has_lexical_risk=True,
    )
    action, trans = selector.select_action(state)
    assert action == Action.ACQUIRE_NETWORK


def test_abstention_on_budget_exhaustion():
    cfg = RAEAConfig(initial_budget=0.0, cost_abstain=0.35)
    selector = ActionSelector(cfg)

    # Con presupuesto 0 y probabilidad incierta, no puede adquirir nada y la abstención domina
    state = DecisionState(
        step=1,
        url="http://test.com",
        x0_features={},
        consulted_modalities=("url", "network"),
        acquisition_statuses={"url": "success", "network": "error"},
        current_probability=0.50,
        remaining_budget=0.0,
        spent_cost=0.5,
        has_lexical_risk=False,
    )
    action, trans = selector.select_action(state)
    assert action == Action.ABSTAIN


def test_decide_next_raea_worker_compatibility():
    # Prueba de compatibilidad hacia atrás con el worker
    action_str, reason, conf, unc = decide_next_raea(
        probability_phishing=0.99,
        consulted=("url",),
        x0_features={},
        step=0,
    )
    assert action_str == "decide"
    assert conf >= 0.99

    # Para una probabilidad ambigua con presupuesto
    action_str, reason, conf, unc = decide_next_raea(
        probability_phishing=0.50,
        consulted=("url",),
        x0_features={"uses_https": 1.0},
        step=0,
    )
    assert action_str == "infrastructure"


def test_end_to_end_run_raea_offline():
    offline_data = {
        "infra_status": "success",
        "content_status": "success",
        "p_m0": 0.01,
        "p_m1": 0.95,
        "p_m2": 0.98,
        "lat_infra_ms": 250.0,
        "lat_content_ms": 400.0,
    }
    x0 = {"has_ip_host": 1.0}  # Guarda activada para impedir salida benigna prematura

    result = run_raea(
        url="http://185.220.101.5/fake",
        x0_features=x0,
        initial_probability=0.01,
        offline_data=offline_data,
    )

    # RAEA debió bloquear la salida benigna en M0, consultar network, observar p_m1=0.95 y clasificar phishing
    assert result.decision == "phishing"
    assert "network" in result.modalities_consulted
    assert len(result.transitions) >= 2
