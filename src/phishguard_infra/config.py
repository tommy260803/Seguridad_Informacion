from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class InfrastructureConfigError(ValueError):
    """Raised when infrastructure analyzer configuration is invalid."""


@dataclass(frozen=True)
class InfrastructureConfig:
    analyzer_version: str
    allowed_ports: dict[str, tuple[int, ...]]
    connect_timeout_seconds: float
    read_timeout_seconds: float
    max_redirects: int
    max_url_length: int
    max_location_length: int
    max_recorded_header_value_length: int
    user_agent: str
    inspect_certificate_after_verification_failure: bool
    require_sandbox_marker: bool
    require_egress_proxy: bool
    egress_proxy_host: str | None
    egress_proxy_port: int | None
    source_path: Path
    raw: dict[str, Any]


def load_infrastructure_config(path: str | Path) -> InfrastructureConfig:
    source_path = Path(path).resolve()
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InfrastructureConfigError(f"Cannot read infrastructure configuration: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise InfrastructureConfigError("Only schema_version 1 is supported")
    ports_raw = raw.get("allowed_ports")
    if not isinstance(ports_raw, dict) or set(ports_raw) != {"http", "https"}:
        raise InfrastructureConfigError("allowed_ports must define http and https")
    analyzer_version = raw.get("analyzer_version")
    if not isinstance(analyzer_version, str) or not analyzer_version.strip():
        raise InfrastructureConfigError("analyzer_version must be a non-empty string")
    ports: dict[str, tuple[int, ...]] = {}
    for scheme, values in ports_raw.items():
        if not isinstance(values, list) or not values:
            raise InfrastructureConfigError(f"allowed_ports.{scheme} must be a non-empty list")
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise InfrastructureConfigError(f"allowed_ports.{scheme} must contain integers")
        parsed = tuple(values)
        if any(port < 1 or port > 65535 for port in parsed):
            raise InfrastructureConfigError("Ports must be in the range 1..65535")
        ports[scheme] = parsed
    numeric_fields = ("connect_timeout_seconds", "read_timeout_seconds")
    integer_fields = (
        "max_redirects",
        "max_url_length",
        "max_location_length",
        "max_recorded_header_value_length",
    )
    if any(
        not isinstance(raw.get(name), (int, float)) or isinstance(raw.get(name), bool)
        for name in numeric_fields
    ):
        raise InfrastructureConfigError("Timeouts must be numeric")
    if any(not isinstance(raw.get(name), int) or isinstance(raw.get(name), bool) for name in integer_fields):
        raise InfrastructureConfigError("Limits must be integers")
    connect_timeout = float(raw["connect_timeout_seconds"])
    read_timeout = float(raw["read_timeout_seconds"])
    max_redirects = raw["max_redirects"]
    max_url_length = raw["max_url_length"]
    max_location_length = raw["max_location_length"]
    max_header = raw["max_recorded_header_value_length"]
    if connect_timeout <= 0 or read_timeout <= 0:
        raise InfrastructureConfigError("Timeouts must be positive")
    if max_redirects < 0 or min(max_url_length, max_location_length, max_header) <= 0:
        raise InfrastructureConfigError("Limits must be positive")
    user_agent = str(raw.get("user_agent") or "").strip()
    if not user_agent or "\r" in user_agent or "\n" in user_agent:
        raise InfrastructureConfigError("A safe descriptive user_agent is required")
    boolean_fields = (
        "inspect_certificate_after_verification_failure",
        "require_sandbox_marker",
        "require_egress_proxy",
    )
    if any(name in raw and not isinstance(raw[name], bool) for name in boolean_fields):
        raise InfrastructureConfigError("Boolean controls must use JSON booleans")
    proxy_url = raw.get("egress_proxy_url")
    proxy_host: str | None = None
    proxy_port: int | None = None
    if proxy_url is not None:
        if not isinstance(proxy_url, str):
            raise InfrastructureConfigError("egress_proxy_url must be a string or null")
        try:
            parsed_proxy = urlsplit(proxy_url)
            proxy_port = parsed_proxy.port
        except ValueError as exc:
            raise InfrastructureConfigError("egress_proxy_url has an invalid authority") from exc
        if (
            parsed_proxy.scheme != "http"
            or not parsed_proxy.hostname
            or proxy_port is None
            or parsed_proxy.username is not None
            or parsed_proxy.password is not None
            or parsed_proxy.path not in ("", "/")
            or parsed_proxy.query
            or parsed_proxy.fragment
        ):
            raise InfrastructureConfigError(
                "egress_proxy_url must be http://host:port without credentials or path"
            )
        proxy_host = parsed_proxy.hostname
    require_proxy = raw.get("require_egress_proxy", True)
    if require_proxy and proxy_host is None:
        raise InfrastructureConfigError("egress_proxy_url is required by policy")
    return InfrastructureConfig(
        analyzer_version=analyzer_version.strip(),
        allowed_ports=ports,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        max_redirects=max_redirects,
        max_url_length=max_url_length,
        max_location_length=max_location_length,
        max_recorded_header_value_length=max_header,
        user_agent=user_agent,
        inspect_certificate_after_verification_failure=raw.get(
            "inspect_certificate_after_verification_failure", False
        ),
        require_sandbox_marker=raw.get("require_sandbox_marker", True),
        require_egress_proxy=require_proxy,
        egress_proxy_host=proxy_host,
        egress_proxy_port=proxy_port,
        source_path=source_path,
        raw=raw,
    )
