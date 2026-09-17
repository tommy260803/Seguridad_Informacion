from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


MODALITIES = ("url", "infrastructure", "content", "visual")


@dataclass(frozen=True)
class AdaptivePolicy:
    uncertainty_threshold: float = 0.20
    minimum_confidence: float = 0.80
    budget: float = 3.0
    costs: dict[str, float] = field(default_factory=lambda: {"infrastructure": 1.0, "content": 1.0, "visual": 1.0})


@dataclass(frozen=True)
class Transition:
    step: int
    state: str
    modality: str | None
    reason: str
    probability_phishing: float | None
    uncertainty: float | None
    budget_remaining: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OrchestrationResult:
    decision: str
    probability_phishing: float
    confidence: float
    uncertainty: float
    modalities_consulted: tuple[str, ...]
    transitions: tuple[Transition, ...]
    cost: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"transitions": [t.to_dict() for t in self.transitions]}
