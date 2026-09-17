from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ContentEvidence:
    feature: str
    value: Any
    source: str
    reliable: bool


@dataclass(frozen=True)
class ContentResult:
    status: str
    content_type: str | None
    bytes_received: int
    truncated: bool
    features: dict[str, float]
    evidence: tuple[ContentEvidence, ...]
    error_code: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
