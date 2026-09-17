import json
from pathlib import Path

import pytest

from phishguard_infra.cli import main


def write_config(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
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
        ),
        encoding="utf-8",
    )
    return path


def test_cli_refuses_network_outside_sandbox(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PHISHGUARD_SANDBOX", raising=False)
    output = tmp_path / "result.json"

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--config",
                str(write_config(tmp_path / "config.json")),
                "--psl",
                "tests/fixtures/public_suffix_list.dat",
                "--url",
                "https://example.com/",
                "--output",
                str(output),
            ]
        )

    assert error.value.code == 2
    assert not output.exists()


def test_cli_rejects_multiline_url_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PHISHGUARD_SANDBOX", "1")
    target_file = tmp_path / "target.txt"
    target_file.write_text("https://example.com/\nhttps://other.example/\n", encoding="utf-8")

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--config",
                str(write_config(tmp_path / "config.json")),
                "--psl",
                "tests/fixtures/public_suffix_list.dat",
                "--url-file",
                str(target_file),
                "--output",
                str(tmp_path / "result.json"),
            ]
        )

    assert error.value.code == 2
