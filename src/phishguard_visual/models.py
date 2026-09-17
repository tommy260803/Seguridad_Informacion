from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class VisualEvidence:
    feature: str
    value: Any
    source: str = "screenshot"
    reliable: bool = True


@dataclass(frozen=True)
class VisualResult:
    status: str
    bytes_received: int
    features: dict[str, float]
    evidence: tuple[VisualEvidence, ...]
    error_code: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
