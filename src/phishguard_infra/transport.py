from __future__ import annotations

import http.client
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from phishguard_infra.config import InfrastructureConfig
from phishguard_infra.models import CertificateInfo, ProbeResponse, TlsInfo, ValidatedTarget


class TransportError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class Transport(Protocol):
    def probe(self, target: ValidatedTarget, observed_at: datetime) -> ProbeResponse: ...


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: ValidatedTarget, timeout: float) -> None:
        super().__init__(target.host, target.port, timeout=timeout)
        self._pinned_ip = target.pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: ValidatedTarget, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(target.host, target.port, timeout=timeout, context=context)
        self._pinned_ip = target.pinned_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


class _ProxyPinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        target: ValidatedTarget,
        proxy_host: str,
        proxy_port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(target.host, target.port, timeout=timeout, context=context)
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self.set_tunnel(target.pinned_ip, target.port)

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._proxy_host, self._proxy_port), self.timeout
        )
        self.sock = raw_socket
        try:
            self._tunnel()
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            self.sock = None
            raise


def _proxy_request_target(target: ValidatedTarget) -> str:
    display_ip = f"[{target.pinned_ip}]" if ":" in target.pinned_ip else target.pinned_ip
    return f"http://{display_ip}:{target.port}{target.request_target}"


def _host_header(target: ValidatedTarget) -> str:
    default_port = 443 if target.scheme == "https" else 80
    display_host = f"[{target.host}]" if ":" in target.host else target.host
    return display_host if target.port == default_port else f"{display_host}:{target.port}"


def _certificate_info(der_bytes: bytes, observed_at: datetime) -> CertificateInfo:
    certificate = x509.load_der_x509_certificate(der_bytes)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    reference = observed_at.astimezone(timezone.utc)
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_count = len(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_count = 0
    public_key = certificate.public_key()
    key_bits = getattr(public_key, "key_size", None)
    return CertificateInfo(
        sha256_fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number_hex=format(certificate.serial_number, "x"),
        not_valid_before=not_before.isoformat().replace("+00:00", "Z"),
        not_valid_after=not_after.isoformat().replace("+00:00", "Z"),
        validity_days=(not_after - not_before).total_seconds() / 86400,
        days_remaining=(not_after - reference).total_seconds() / 86400,
        self_issued=certificate.subject == certificate.issuer,
        san_dns_count=san_count,
        signature_algorithm_oid=certificate.signature_algorithm_oid.dotted_string,
        public_key_type=type(public_key).__name__,
        public_key_bits=int(key_bits) if key_bits is not None else None,
    )


def _certificate_chain_fingerprints(tls_socket: object, verified: bool) -> tuple[str, ...]:
    method_name = "get_verified_chain" if verified else "get_unverified_chain"
    method = getattr(tls_socket, method_name, None)
    if method is None:
        return ()
    try:
        chain = method()
    except (OSError, ssl.SSLError):
        return ()
    return tuple(hashlib.sha256(der_bytes).hexdigest() for der_bytes in chain)


class PinnedHttpTransport:
    _RECORDED_HEADERS = frozenset({"location", "server", "content-type", "strict-transport-security"})

    def __init__(self, config: InfrastructureConfig) -> None:
        self.config = config

    def _request(
        self,
        target: ValidatedTarget,
        observed_at: datetime,
        context: ssl.SSLContext | None,
        verified: bool,
        verification_error: str | None,
    ) -> ProbeResponse:
        started = time.perf_counter()
        connection: http.client.HTTPConnection
        proxy = (
            (self.config.egress_proxy_host, self.config.egress_proxy_port)
            if self.config.egress_proxy_host is not None
            and self.config.egress_proxy_port is not None
            else None
        )
        request_target = target.request_target
        if target.scheme == "https":
            if context is None:
                raise TransportError("tls_context_missing", "HTTPS requires an SSL context")
            if proxy is None:
                connection = _PinnedHTTPSConnection(
                    target, self.config.connect_timeout_seconds, context
                )
            else:
                connection = _ProxyPinnedHTTPSConnection(
                    target,
                    proxy[0],
                    proxy[1],
                    self.config.connect_timeout_seconds,
                    context,
                )
        else:
            if proxy is None:
                connection = _PinnedHTTPConnection(target, self.config.connect_timeout_seconds)
            else:
                connection = http.client.HTTPConnection(
                    proxy[0], proxy[1], timeout=self.config.connect_timeout_seconds
                )
                request_target = _proxy_request_target(target)
        try:
            connection.connect()
            if connection.sock is None:
                raise TransportError("connect_error", "Connection did not create a socket")
            connection.sock.settimeout(self.config.read_timeout_seconds)
            tls_info = None
            if target.scheme == "https":
                tls_socket = connection.sock
                der_bytes = tls_socket.getpeercert(binary_form=True)  # type: ignore[attr-defined]
                cipher_value = tls_socket.cipher()  # type: ignore[attr-defined]
                tls_info = TlsInfo(
                    verified=verified,
                    verification_error=verification_error,
                    version=tls_socket.version(),  # type: ignore[attr-defined]
                    cipher=cipher_value[0] if cipher_value else None,
                    certificate=_certificate_info(der_bytes, observed_at) if der_bytes else None,
                    chain_sha256_fingerprints=_certificate_chain_fingerprints(
                        tls_socket, verified
                    ),
                )
            connection.request(
                "HEAD",
                request_target,
                headers={
                    "Host": _host_header(target),
                    "User-Agent": self.config.user_agent,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            headers = tuple(
                (
                    name.lower(),
                    value[: self.config.max_recorded_header_value_length],
                )
                for name, value in response.getheaders()
                if name.lower() in self._RECORDED_HEADERS
            )
            status_code = response.status
            reason = (response.reason or "")[:128]
            response.close()
            return ProbeResponse(
                status_code=status_code,
                reason=reason,
                headers=headers,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                tls=tls_info,
            )
        finally:
            connection.close()

    def probe(self, target: ValidatedTarget, observed_at: datetime) -> ProbeResponse:
        try:
            if target.scheme == "http":
                return self._request(target, observed_at, None, False, None)
            return self._request(target, observed_at, ssl.create_default_context(), True, None)
        except ssl.SSLCertVerificationError as exc:
            if not self.config.inspect_certificate_after_verification_failure:
                raise TransportError("tls_verification_failed", str(exc)[:256]) from exc
            error = str(exc)[:256]
            try:
                return self._request(
                    target,
                    observed_at,
                    ssl._create_unverified_context(),
                    False,
                    error,
                )
            except (OSError, ssl.SSLError, http.client.HTTPException) as fallback_exc:
                raise TransportError("tls_inspection_failed", str(fallback_exc)[:256]) from fallback_exc
        except socket.timeout as exc:
            raise TransportError("timeout", "Connection or read timed out") from exc
        except ssl.SSLError as exc:
            raise TransportError("tls_error", str(exc)[:256]) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise TransportError("network_error", str(exc)[:256]) from exc
