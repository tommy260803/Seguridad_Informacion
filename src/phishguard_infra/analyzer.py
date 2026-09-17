from __future__ import annotations

import ipaddress
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

from phishguard_data.psl import PublicSuffixList
from phishguard_infra.config import InfrastructureConfig
from phishguard_infra.models import Evidence, HopRecord, InfrastructureResult
from phishguard_infra.policy import TargetPolicy, UnsafeTargetError
from phishguard_infra.resolver import Resolver
from phishguard_infra.transport import Transport, TransportError


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class InfrastructureAnalyzer:
    def __init__(
        self,
        config: InfrastructureConfig,
        psl: PublicSuffixList,
        resolver: Resolver,
        transport: Transport,
    ) -> None:
        self.config = config
        self.psl = psl
        self.resolver = resolver
        self.transport = transport
        self.policy = TargetPolicy(config)

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _features(self, hops: list[HopRecord]) -> dict[str, float]:
        if not hops:
            return {"infrastructure_available": 0.0}
        initial_addresses = [ipaddress.ip_address(value) for value in hops[0].resolved_addresses]
        redirect_count = sum(
            hop.status_code in _REDIRECT_STATUSES and hop.location is not None for hop in hops
        )
        host_changes = 0
        domain_changes = 0
        for previous, current in zip(hops, hops[1:]):
            host_changes += previous.host != current.host
            domain_changes += (
                self.psl.registrable_domain(previous.host)
                != self.psl.registrable_domain(current.host)
            )
        tls_hops = [hop.tls for hop in hops if hop.tls is not None]
        certificates = [tls.certificate for tls in tls_hops if tls.certificate is not None]
        features: dict[str, float] = {
            "infrastructure_available": 1.0,
            "dns_address_count_initial": float(len(initial_addresses)),
            "dns_ipv4_count_initial": float(sum(address.version == 4 for address in initial_addresses)),
            "dns_ipv6_count_initial": float(sum(address.version == 6 for address in initial_addresses)),
            "redirect_count": float(redirect_count),
            "redirect_host_change_count": float(host_changes),
            "redirect_registered_domain_change_count": float(domain_changes),
            "tls_hop_count": float(len(tls_hops)),
            "tls_verification_failure_count": float(sum(not tls.verified for tls in tls_hops)),
            "tls_max_chain_length": float(
                max((len(tls.chain_sha256_fingerprints) for tls in tls_hops), default=0)
            ),
            "certificate_available": float(bool(certificates)),
            "final_status_code": float(hops[-1].status_code),
            "final_uses_https": float(hops[-1].scheme == "https"),
            "total_dns_ms": float(sum(hop.dns_elapsed_ms for hop in hops)),
            "total_request_ms": float(sum(hop.request_elapsed_ms for hop in hops)),
        }
        if certificates:
            features.update(
                {
                    "certificate_min_days_remaining": float(
                        min(certificate.days_remaining for certificate in certificates)
                    ),
                    "certificate_min_validity_days": float(
                        min(certificate.validity_days for certificate in certificates)
                    ),
                    "certificate_self_issued_count": float(
                        sum(certificate.self_issued for certificate in certificates)
                    ),
                    "certificate_max_san_dns_count": float(
                        max(certificate.san_dns_count for certificate in certificates)
                    ),
                }
            )
        return features

    def _evidence(self, features: dict[str, float], observed_at: str, hops: int) -> tuple[Evidence, ...]:
        return tuple(
            Evidence(
                source="infrastructure",
                feature=name,
                value=value,
                normalized_value=None,
                reliability=1.0,
                observed_at=observed_at,
                provenance={"analyzer_version": self.config.analyzer_version, "hop_count": hops},
            )
            for name, value in sorted(features.items())
        )

    def analyze(self, url: str, now: datetime | None = None) -> InfrastructureResult:
        started = time.perf_counter()
        observed_datetime = now or datetime.now(timezone.utc)
        observed_at = self._timestamp(observed_datetime)
        current_url = url
        visited: set[str] = set()
        hops: list[HopRecord] = []
        error_code: str | None = None
        error_detail: str | None = None
        status = "success"

        for ordinal in range(self.config.max_redirects + 1):
            try:
                normalized_url, _, host, port, _ = self.policy.parse_url(current_url)
                if normalized_url in visited:
                    raise UnsafeTargetError("redirect_cycle", "Redirect cycle detected")
                visited.add(normalized_url)
                resolution = self.resolver.resolve(host, port)
                target = self.policy.validate_resolution(normalized_url, resolution)
                response = self.transport.probe(target, observed_datetime)
            except UnsafeTargetError as exc:
                status, error_code, error_detail = "blocked", exc.code, exc.detail
                break
            except (socket.gaierror, TimeoutError) as exc:
                status, error_code, error_detail = "error", "dns_error", str(exc)[:256]
                break
            except TransportError as exc:
                status, error_code, error_detail = "error", exc.code, exc.detail
                break

            location = response.header("location")
            hops.append(
                HopRecord(
                    ordinal=ordinal,
                    url=target.url,
                    scheme=target.scheme,
                    host=target.host,
                    port=target.port,
                    resolved_addresses=target.addresses,
                    pinned_ip=target.pinned_ip,
                    dns_elapsed_ms=target.dns_elapsed_ms,
                    request_elapsed_ms=response.elapsed_ms,
                    status_code=response.status_code,
                    location=location,
                    tls=response.tls,
                )
            )
            if response.status_code not in _REDIRECT_STATUSES or location is None:
                break
            if len(location) > self.config.max_location_length:
                status, error_code, error_detail = "blocked", "location_length", "Redirect location is too long"
                break
            if ordinal >= self.config.max_redirects:
                status, error_code, error_detail = "error", "redirect_limit", "Redirect limit reached"
                break
            current_url = urljoin(target.url, location)

        features = self._features(hops)
        if status != "success" and hops:
            features["infrastructure_partial"] = 1.0
        final_url = hops[-1].url if hops else None
        return InfrastructureResult(
            status=status,
            initial_url=url,
            final_url=final_url,
            observed_at=observed_at,
            analyzer_version=self.config.analyzer_version,
            hops=tuple(hops),
            features=features,
            evidence=self._evidence(features, observed_at, len(hops)),
            total_elapsed_ms=(time.perf_counter() - started) * 1000,
            error_code=error_code,
            error_detail=error_detail,
        )
