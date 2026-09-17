import json
from pathlib import Path

import pytest

from phishguard_infra.config import load_infrastructure_config
from phishguard_infra.models import Resolution
from phishguard_infra.policy import TargetPolicy, UnsafeTargetError


def write_config(path: Path, **overrides: object) -> Path:
    raw = {
        "schema_version": 1,
        "analyzer_version": "test-1",
        "allowed_ports": {"http": [80], "https": [443]},
        "connect_timeout_seconds": 1,
        "read_timeout_seconds": 1,
        "max_redirects": 3,
        "max_url_length": 2048,
        "max_location_length": 2048,
        "max_recorded_header_value_length": 128,
        "user_agent": "infra-test/1",
        "inspect_certificate_after_verification_failure": True,
        "require_sandbox_marker": True,
        "require_egress_proxy": False,
        "egress_proxy_url": None,
    }
    raw.update(overrides)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


@pytest.fixture
def policy(tmp_path: Path) -> TargetPolicy:
    return TargetPolicy(load_infrastructure_config(write_config(tmp_path / "config.json")))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_policy_blocks_non_public_and_transition_addresses(
    policy: TargetPolicy, address: str
) -> None:
    resolution = Resolution("public.example.com", (address,), 1.0)

    with pytest.raises(UnsafeTargetError) as error:
        policy.validate_resolution("https://public.example.com/", resolution)

    assert error.value.code == "blocked_address"


def test_policy_accepts_and_deterministically_pins_public_addresses(policy: TargetPolicy) -> None:
    resolution = Resolution(
        "public.example.com",
        ("2606:4700:4700::1111", "8.8.8.8", "1.1.1.1", "8.8.8.8"),
        2.5,
    )

    target = policy.validate_resolution("https://public.example.com/a?q=ñ", resolution)

    assert target.addresses == ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111")
    assert target.pinned_ip == "1.1.1.1"
    assert target.request_target == "/a?q=%C3%B1"


def test_policy_rejects_a_mixed_public_private_dns_answer(policy: TargetPolicy) -> None:
    resolution = Resolution("public.example.com", ("8.8.8.8", "10.0.0.4"), 1.0)

    with pytest.raises(UnsafeTargetError) as error:
        policy.validate_resolution("https://public.example.com/", resolution)

    assert error.value.code == "blocked_address"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://example.com/a", "disallowed_scheme"),
        ("https://user:pass@example.com/", "userinfo_not_allowed"),
        ("https://example.com:8443/", "disallowed_port"),
        ("http://localhost/", "blocked_hostname"),
        ("http://metadata.google.internal/", "blocked_hostname"),
        ("http://service.local/", "blocked_hostname"),
        ("http://local/", "blocked_hostname"),
    ],
)
def test_policy_rejects_unsafe_url_forms(policy: TargetPolicy, url: str, code: str) -> None:
    with pytest.raises(UnsafeTargetError) as error:
        policy.parse_url(url)

    assert error.value.code == code
