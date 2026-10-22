from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Action(str, Enum):
    STOP_PHISHING = "stop_phishing"
    STOP_BENIGN = "stop_benign"
    ACQUIRE_NETWORK = "acquire_network"
    ACQUIRE_HTML = "acquire_html"
    ACQUIRE_VISUAL = "acquire_visual"
    ABSTAIN = "abstain"


class AcquisitionStatus(str, Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class DecisionState:
    step: int
    url: str
    x0_features: Dict[str, float]
    consulted_modalities: Tuple[str, ...]
    acquisition_statuses: Dict[str, str]
    current_probability: float
    remaining_budget: float
    spent_cost: float
    has_lexical_risk: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RAEAConfig:
    gamma: float = 15.0               # C_FN / C_FP
    c_fp: float = 1.0                 # C_FP
    cost_abstain: float = 0.35        # C_abstain
    lambda_cost: float = 0.25         # trade-off factor lambda
    p_safe: float = 0.02              # max probability for early benign stop at M0
    tau_avail_min: float = 0.10       # minimum expected availability to allow acquisition
    initial_budget: float = 3.0       # total normalized cost budget
    enforce_benign_guard: bool = True # Ablation flag: disable benign guard
    enable_availability: bool = True  # Ablation flag: disable availability estimator
    enable_asymmetric_cost: bool = True # Ablation flag: symmetric costs (gamma=1)
    enable_abstention: bool = True    # Ablation flag: disable abstention
    enable_information_value: bool = True # Ablation flag: ignore expected risk reduction


@dataclass(frozen=True)
class TransitionLog:
    step: int
    action: Action
    probability_phishing: float
    risk_phishing: float
    risk_benign: float
    risk_abstain: float
    q_values: Dict[str, float]
    estimated_availability: Optional[float]
    estimated_cost: Optional[float]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        return d


@dataclass(frozen=True)
class RAEAExecutionResult:
    decision: str  # "phishing", "legitimate", "uncertain"
    probability_phishing: float
    modalities_consulted: Tuple[str, ...]
    total_cost: float
    abstained: bool
    transitions: Tuple[TransitionLog, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "probability_phishing": self.probability_phishing,
            "modalities_consulted": list(self.modalities_consulted),
            "total_cost": self.total_cost,
            "abstained": self.abstained,
            "transitions": [t.to_dict() for t in self.transitions],
        }
