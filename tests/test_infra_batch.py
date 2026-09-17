import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from phishguard_infra.batch import (
    PilotConfigError,
    load_pilot_config,
    prepare_pilot,
    run_pilot,
    select_pilot,
)
from phishguard_infra.models import InfrastructureResult


def write_config(path: Path, **overrides: object) -> Path:
    raw = {
        "schema_version": 1,
        "pilot_version": "pilot-test-1",
        "split": "conventional",
        "sample_size": 4,
        "seed": 42,
        "partitions": ["train", "validation"],
        "labels": ["legitimate", "phishing"],
        "url_origins": ["reported_url", "constructed_from_domain"],
        "max_per_registered_domain": 1,
        "delay_seconds": 0,
    }
    raw.update(overrides)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def write_dataset(path: Path) -> Path:
    path.mkdir()
    (path / "splits").mkdir()
    fields = [
        "sample_id",
        "canonical_url",
        "canonical_url_sha256",
        "registered_domain",
        "label",
        "observed_at",
        "url_origin",
    ]
    rows = [
        ["l1", "https://one.test/", "h1", "one.test", "legitimate", "2026-09-16T10:00:00Z", "constructed_from_domain"],
        ["l2", "https://two.test/", "h2", "two.test", "legitimate", "2026-09-16T10:00:00Z", "constructed_from_domain"],
        ["p1", "https://bad.test/a", "h3", "bad.test", "phishing", "2026-09-16T10:00:00Z", "reported_url"],
        ["p2", "https://worse.test/a", "h4", "worse.test", "phishing", "2026-09-16T10:00:00Z", "reported_url"],
        ["same1", "https://same.test/a", "h5", "same.test", "phishing", "2026-09-16T10:00:00Z", "reported_url"],
        ["same2", "https://same.test/b", "h6", "same.test", "phishing", "2026-09-16T10:00:00Z", "reported_url"],
        ["heldout", "https://heldout.test/", "h7", "heldout.test", "phishing", "2026-09-16T10:00:00Z", "reported_url"],
    ]
    with (path / "samples.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(fields)
        writer.writerows(rows)
    assignments = [
        ("l1", "train"),
        ("p1", "train"),
        ("same1", "train"),
        ("l2", "validation"),
        ("p2", "validation"),
        ("same2", "validation"),
        ("heldout", "test"),
    ]
    with (path / "splits" / "conventional.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["sample_id", "partition"])
        writer.writerows(assignments)
    return path


def test_selection_is_deterministic_balanced_and_excludes_test(tmp_path: Path) -> None:
    dataset = write_dataset(tmp_path / "dataset")
    config = load_pilot_config(write_config(tmp_path / "pilot.json"))

    first = select_pilot(config, dataset)
    second = select_pilot(config, dataset)

    assert first == second
    assert {sample.partition for sample in first} == {"train", "validation"}
    assert {sample.label for sample in first} == {"legitimate", "phishing"}
    assert "heldout" not in {sample.sample_id for sample in first}
    domains = [sample.registered_domain for sample in first]
    assert len(domains) == len(set(domains))


def test_config_refuses_test_partition(tmp_path: Path) -> None:
    path = write_config(tmp_path / "pilot.json", partitions=["test"])

    with pytest.raises(PilotConfigError):
        load_pilot_config(path)


def test_plan_summary_contains_no_urls(tmp_path: Path) -> None:
    dataset = write_dataset(tmp_path / "dataset")
    config = load_pilot_config(write_config(tmp_path / "pilot.json"))

    _, summary = prepare_pilot(config, dataset, tmp_path / "output")

    assert summary["selected"] == 4
    assert summary["unique_registered_domains"] == 4
    assert "https://" not in json.dumps(summary)


class FakeAnalyzer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def analyze(self, url: str) -> InfrastructureResult:
        self.calls.append(url)
        return InfrastructureResult(
            status="success",
            initial_url=url,
            final_url=url,
            observed_at=datetime(2026, 9, 16, 10, 1, tzinfo=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            analyzer_version="fake-1",
            hops=(),
            features={"infrastructure_available": 1.0},
            evidence=(),
            total_elapsed_ms=10.0,
        )


def test_runner_checkpoints_and_resumes_without_duplicate_requests(tmp_path: Path) -> None:
    dataset = write_dataset(tmp_path / "dataset")
    config = load_pilot_config(write_config(tmp_path / "pilot.json"))
    output = tmp_path / "output"
    first_analyzer = FakeAnalyzer()

    first_report = run_pilot(config, dataset, output, first_analyzer)
    second_analyzer = FakeAnalyzer()
    resumed_report = run_pilot(config, dataset, output, second_analyzer)

    assert len(first_analyzer.calls) == 4
    assert not second_analyzer.calls
    assert first_report == resumed_report
    assert resumed_report["attempted"] == 4
    assert resumed_report["remaining"] == 0
    assert resumed_report["infrastructure_coverage"] == 1.0
    lines = (output / "results.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert all(json.loads(line)["acquisition_lag_seconds"] == 60.0 for line in lines)
