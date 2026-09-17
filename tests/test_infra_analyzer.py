import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from phishguard_data.psl import PublicSuffixList
from phishguard_infra.analyzer import InfrastructureAnalyzer
from phishguard_infra.config import load_infrastructure_config
from phishguard_infra.models import ProbeResponse, Resolution, TlsInfo, ValidatedTarget


def config(path: Path, max_redirects: int = 3):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "analyzer_version": "infra-test-1",
                "allowed_ports": {"http": [80], "https": [443]},
                "connect_timeout_seconds": 1,
                "read_timeout_seconds": 1,
                "max_redirects": max_redirects,
                "max_url_length": 2048,
                "max_location_length": 2048,
                "max_recorded_header_value_length": 128,
                "user_agent": "infra-test/1",
                "inspect_certificate_after_verification_failure": True,
                "require_sandbox_marker": True,
                "require_egress_proxy": False,
                "egress_proxy_url": None,
            }
        ),
        encoding="utf-8",
    )
    return load_infrastructure_config(path)


class FakeResolver:
    def __init__(self, values: dict[str, tuple[str, ...]]) -> None:
        self.values = values
        self.calls: Counter[str] = Counter()

    def resolve(self, host: str, port: int) -> Resolution:
        self.calls[host] += 1
        return Resolution(host, self.values[host], 1.25)


class FakeTransport:
    def __init__(self, responses: dict[str, ProbeResponse]) -> None:
        self.responses = responses
        self.targets: list[ValidatedTarget] = []

    def probe(self, target: ValidatedTarget, observed_at: datetime) -> ProbeResponse:
        self.targets.append(target)
        return self.responses[target.host]


def response(status: int, location: str | None = None, tls: bool = True) -> ProbeResponse:
    headers = (("location", location),) if location else ()
    tls_info = TlsInfo(True, None, "TLSv1.3", "TLS_AES_256_GCM_SHA384", None) if tls else None
    return ProbeResponse(status, "test", headers, 2.5, tls_info)


def analyzer(tmp_path: Path, resolver: FakeResolver, transport: FakeTransport, redirects: int = 3):
    psl = PublicSuffixList.from_file(Path("tests/fixtures/public_suffix_list.dat"))
    return InfrastructureAnalyzer(config(tmp_path / "config.json", redirects), psl, resolver, transport)


def test_redirects_are_re_resolved_and_domain_changes_are_recorded(tmp_path: Path) -> None:
    resolver = FakeResolver(
        {
            "a.example.com": ("8.8.8.8",),
            "b.other.org": ("1.1.1.1", "2606:4700:4700::1111"),
        }
    )
    transport = FakeTransport(
        {
            "a.example.com": response(302, "https://b.other.org/login"),
            "b.other.org": response(200),
        }
    )

    result = analyzer(tmp_path, resolver, transport).analyze(
        "https://a.example.com/start", datetime(2026, 9, 16, tzinfo=timezone.utc)
    )

    assert result.status == "success"
    assert len(result.hops) == 2
    assert result.features["redirect_count"] == 1.0
    assert result.features["redirect_host_change_count"] == 1.0
    assert result.features["redirect_registered_domain_change_count"] == 1.0
    assert resolver.calls == {"a.example.com": 1, "b.other.org": 1}
    assert [target.pinned_ip for target in transport.targets] == ["8.8.8.8", "1.1.1.1"]


def test_redirect_to_private_address_is_blocked_before_transport(tmp_path: Path) -> None:
    resolver = FakeResolver(
        {"a.example.com": ("8.8.8.8",), "private.example.com": ("127.0.0.1",)}
    )
    transport = FakeTransport(
        {"a.example.com": response(302, "http://private.example.com/admin", tls=False)}
    )

    result = analyzer(tmp_path, resolver, transport).analyze("https://a.example.com/")

    assert result.status == "blocked"
    assert result.error_code == "blocked_address"
    assert len(result.hops) == 1
    assert result.features["infrastructure_partial"] == 1.0
    assert len(transport.targets) == 1


def test_redirect_cycle_stops_before_second_network_request(tmp_path: Path) -> None:
    resolver = FakeResolver({"a.example.com": ("8.8.8.8",)})
    transport = FakeTransport({"a.example.com": response(301, "/start")})

    result = analyzer(tmp_path, resolver, transport).analyze("https://a.example.com/start")

    assert result.status == "blocked"
    assert result.error_code == "redirect_cycle"
    assert resolver.calls["a.example.com"] == 1
    assert len(transport.targets) == 1


def test_redirect_limit_is_reported(tmp_path: Path) -> None:
    resolver = FakeResolver({"a.example.com": ("8.8.8.8",)})
    transport = FakeTransport({"a.example.com": response(302, "/next")})

    result = analyzer(tmp_path, resolver, transport, redirects=0).analyze("https://a.example.com/start")

    assert result.status == "error"
    assert result.error_code == "redirect_limit"
    assert result.features["redirect_count"] == 1.0


def test_initial_private_target_returns_blocked_without_evidence_fetch(tmp_path: Path) -> None:
    resolver = FakeResolver({"private.example.com": ("10.0.0.1",)})
    transport = FakeTransport({})

    result = analyzer(tmp_path, resolver, transport).analyze("http://private.example.com/")

    assert result.status == "blocked"
    assert result.final_url is None
    assert result.features == {"infrastructure_available": 0.0}
    assert not transport.targets
