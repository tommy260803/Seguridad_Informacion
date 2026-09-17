from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from phishguard_infra.models import ValidatedTarget
from phishguard_infra.transport import (
    _PinnedHTTPConnection,
    _PinnedHTTPSConnection,
    _ProxyPinnedHTTPSConnection,
    _certificate_chain_fingerprints,
    _certificate_info,
    _host_header,
    _proxy_request_target,
)


def target(scheme: str = "https", port: int = 443) -> ValidatedTarget:
    return ValidatedTarget(
        f"{scheme}://example.com/",
        scheme,
        "example.com",
        port,
        "/",
        ("8.8.8.8",),
        "8.8.8.8",
        1.0,
    )


def test_pinned_connection_preserves_original_http_host() -> None:
    connection = _PinnedHTTPConnection(target("http", 80), 4.0)

    connection.putrequest("HEAD", "/")

    request_headers = b"\r\n".join(connection._buffer)  # type: ignore[attr-defined]
    assert b"Host: example.com" in request_headers


def test_proxy_target_uses_pinned_ip_and_original_host_header() -> None:
    pinned_target = target("http", 80)

    assert _proxy_request_target(pinned_target) == "http://8.8.8.8:80/"
    assert _host_header(pinned_target) == "example.com"


def test_proxy_https_connects_to_proxy_then_uses_pinned_ip_and_sni(monkeypatch) -> None:
    calls = {}

    class RawSocket:
        def close(self) -> None:
            calls["closed"] = True

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            calls["server_hostname"] = server_hostname
            return raw_socket

    def create_connection(address, timeout):
        calls["address"] = address
        return RawSocket()

    monkeypatch.setattr("phishguard_infra.transport.socket.create_connection", create_connection)
    connection = _ProxyPinnedHTTPSConnection(
        target(), "egress-proxy", 3128, 4.0, Context()  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        connection,
        "_tunnel",
        lambda: calls.update(
            tunnel_host=connection._tunnel_host, tunnel_port=connection._tunnel_port
        ),
    )

    connection.connect()

    assert calls["address"] == ("egress-proxy", 3128)
    assert calls["tunnel_host"] == "8.8.8.8"
    assert calls["tunnel_port"] == 443
    assert calls["server_hostname"] == "example.com"


def test_pinned_https_connection_uses_ip_and_original_sni(monkeypatch) -> None:
    calls = {}

    class RawSocket:
        def close(self) -> None:
            calls["closed"] = True

    class WrappedSocket:
        pass

    class Context:
        def wrap_socket(self, raw_socket, server_hostname):
            calls["server_hostname"] = server_hostname
            calls["raw_socket"] = raw_socket
            return WrappedSocket()

    raw = RawSocket()

    def create_connection(address, timeout):
        calls["address"] = address
        calls["timeout"] = timeout
        return raw

    monkeypatch.setattr("phishguard_infra.transport.socket.create_connection", create_connection)
    connection = _PinnedHTTPSConnection(target(), 4.0, Context())  # type: ignore[arg-type]

    connection.connect()

    assert calls["address"] == ("8.8.8.8", 443)
    assert calls["server_hostname"] == "example.com"


def test_certificate_metadata_is_extracted_from_der() -> None:
    now = datetime(2026, 9, 16, tzinfo=timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1234)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=29))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)

    info = _certificate_info(der, now)

    assert info.self_issued is True
    assert info.san_dns_count == 1
    assert info.public_key_bits == 2048
    assert 28.9 < info.days_remaining < 29.1
    assert len(info.sha256_fingerprint) == 64


def test_certificate_chain_is_reduced_to_reproducible_fingerprints() -> None:
    class TlsSocket:
        def get_verified_chain(self):
            return [b"leaf", b"issuer"]

    fingerprints = _certificate_chain_fingerprints(TlsSocket(), verified=True)

    assert fingerprints == (
        "9f91161f43433e49a6de6db680d79f60159f2e4ac9172621a12846428158440b",
        "535c6f8eb511f5d966a1b0725df92ebf27514faba945cbbd698e23ac72c41757",
    )
