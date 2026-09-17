import json
from pathlib import Path

import pytest

from phishguard_infra.config import InfrastructureConfigError, load_infrastructure_config


def valid_config() -> dict[str, object]:
    return {
        "schema_version": 1,
        "analyzer_version": "test-1",
        "allowed_ports": {"http": [80], "https": [443]},
        "connect_timeout_seconds": 2,
        "read_timeout_seconds": 3,
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


def write_config(path: Path, raw: dict[str, object]) -> Path:
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analyzer_version", ""),
        ("connect_timeout_seconds", "2"),
        ("max_redirects", 1.5),
        ("require_sandbox_marker", "false"),
        ("inspect_certificate_after_verification_failure", 1),
        ("require_egress_proxy", "false"),
    ],
)
def test_config_rejects_ambiguous_types(
    tmp_path: Path, field: str, value: object
) -> None:
    raw = valid_config()
    raw[field] = value

    with pytest.raises(InfrastructureConfigError):
        load_infrastructure_config(write_config(tmp_path / "config.json", raw))


def test_config_rejects_boolean_port(tmp_path: Path) -> None:
    raw = valid_config()
    raw["allowed_ports"] = {"http": [True], "https": [443]}

    with pytest.raises(InfrastructureConfigError):
        load_infrastructure_config(write_config(tmp_path / "config.json", raw))


def test_config_requires_proxy_url_when_policy_demands_it(tmp_path: Path) -> None:
    raw = valid_config()
    raw["require_egress_proxy"] = True

    with pytest.raises(InfrastructureConfigError, match="required by policy"):
        load_infrastructure_config(write_config(tmp_path / "config.json", raw))


@pytest.mark.parametrize(
    "proxy_url",
    [
        "https://proxy.test:3128",
        "http://user:secret@proxy.test:3128",
        "http://proxy.test:3128/path",
        "http://proxy.test",
    ],
)
def test_config_rejects_unsafe_proxy_urls(tmp_path: Path, proxy_url: str) -> None:
    raw = valid_config()
    raw["egress_proxy_url"] = proxy_url

    with pytest.raises(InfrastructureConfigError):
        load_infrastructure_config(write_config(tmp_path / "config.json", raw))
