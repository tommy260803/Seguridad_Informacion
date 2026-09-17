from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SourceRecord:
    source: str
    source_record_id: str
    raw_url: str
    label: str
    source_timestamp: str | None
    observed_at: str
    target: str | None = None
    rank: int | None = None
    url_origin: str = "reported_url"


@dataclass(frozen=True)
class Sample:
    sample_id: str
    canonical_url: str
    canonical_url_sha256: str
    label: str
    source: str
    source_record_id: str
    source_timestamp: str | None
    observed_at: str
    first_observed_at: str
    scheme: str
    host: str
    registered_domain: str
    has_userinfo: bool
    target: str | None
    rank: int | None
    url_origin: str
    snapshot_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
