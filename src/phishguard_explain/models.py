from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    source: str
    feature: str
    value: Any
    contribution: float
    reliable: bool = True


@dataclass(frozen=True)
class Explanation:
    decision: str
    summary: str
    reasons: tuple[dict[str, Any], ...]
    evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
