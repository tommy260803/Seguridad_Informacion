"""RAEA-Phish: Risk- and Availability-Aware Adaptive Evidence Acquisition.
Experimental adaptive evidence acquisition module for PhishPe.
"""
from phishguard_orchestrator.raea.models import (
    Action,
    AcquisitionStatus,
    DecisionState,
    RAEAConfig,
    RAEAExecutionResult,
    TransitionLog,
)
from phishguard_orchestrator.raea.risk import RiskEstimator
from phishguard_orchestrator.raea.availability import AvailabilityEstimator
from phishguard_orchestrator.raea.cost import AcquisitionCostEstimator
from phishguard_orchestrator.raea.policy import (
    AbstentionHandler,
    ActionSelector,
    RiskAvailabilityAwarePolicy,
)
from phishguard_orchestrator.raea.adapter import EvidenceAcquisitionAdapter
from phishguard_orchestrator.raea.logger import DecisionLogger
from phishguard_orchestrator.raea.engine import run_raea, evaluate_lexical_risk

__all__ = [
    "Action",
    "AcquisitionStatus",
    "DecisionState",
    "RAEAConfig",
    "RAEAExecutionResult",
    "TransitionLog",
    "RiskEstimator",
    "AvailabilityEstimator",
    "AcquisitionCostEstimator",
    "AbstentionHandler",
    "ActionSelector",
    "RiskAvailabilityAwarePolicy",
    "EvidenceAcquisitionAdapter",
    "DecisionLogger",
    "run_raea",
    "evaluate_lexical_risk",
]
