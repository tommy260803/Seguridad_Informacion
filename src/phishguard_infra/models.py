from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Resolution:
    host: str
    addresses: tuple[str, ...]
    elapsed_ms: float


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    host: str
    port: int
    request_target: str
    addresses: tuple[str, ...]
    pinned_ip: str
    dns_elapsed_ms: float


@dataclass(frozen=True)
class CertificateInfo:
    sha256_fingerprint: str
    subject: str
    issuer: str
    serial_number_hex: str
    not_valid_before: str
    not_valid_after: str
    validity_days: float
    days_remaining: float
    self_issued: bool
    san_dns_count: int
    signature_algorithm_oid: str
    public_key_type: str
    public_key_bits: int | None


@dataclass(frozen=True)
class TlsInfo:
    verified: bool
    verification_error: str | None
    version: str | None
    cipher: str | None
    certificate: CertificateInfo | None
    chain_sha256_fingerprints: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeResponse:
    status_code: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    elapsed_ms: float
    tls: TlsInfo | None

    def header(self, name: str) -> str | None:
        expected = name.lower()
        return next((value for key, value in self.headers if key.lower() == expected), None)


@dataclass(frozen=True)
class HopRecord:
    ordinal: int
    url: str
    scheme: str
    host: str
    port: int
    resolved_addresses: tuple[str, ...]
    pinned_ip: str
    dns_elapsed_ms: float
    request_elapsed_ms: float
    status_code: int
    location: str | None
    tls: TlsInfo | None


@dataclass(frozen=True)
class Evidence:
    source: str
    feature: str
    value: Any
    normalized_value: float | None
    reliability: float
    observed_at: str
    provenance: dict[str, Any]


@dataclass(frozen=True)
class InfrastructureResult:
    status: str
    initial_url: str
    final_url: str | None
    observed_at: str
    analyzer_version: str
    hops: tuple[HopRecord, ...]
    features: dict[str, float]
    evidence: tuple[Evidence, ...]
    total_elapsed_ms: float
    error_code: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
