import json
from pathlib import Path

import pytest

from phishguard_ml.comparison import compare_m0_m1


def write_artifact(path: Path, experiment: str, offset: float) -> None:
    path.mkdir()
    partitions = {}
    for partition in ("train", "validation", "test"):
        partitions[partition] = {
            "selected_threshold": {
                "f1": 0.5 + offset,
                "recall": 0.6 + offset,
                "precision": 0.7,
                "false_positive_rate": 0.1 - offset,
                "pr_auc": 0.8 + offset,
                "roc_auc": 0.9,
                "brier_score": 0.2 - offset,
                "expected_calibration_error": 0.03,
            }
        }
    (path / "metrics.json").write_text(json.dumps({"partitions": partitions}), encoding="utf-8")
    (path / "manifest.json").write_text(
        json.dumps(
            {
                "experiment_version": experiment,
                "split": "conventional",
                "inputs": {"samples_csv_sha256": "samples", "split_csv_sha256": "split"},
            }
        ),
        encoding="utf-8",
    )


def test_comparison_calculates_deltas_and_writes_report(tmp_path: Path) -> None:
    write_artifact(tmp_path / "m0", "m0", 0.0)
    write_artifact(tmp_path / "m1", "m1", 0.1)

    report = compare_m0_m1(tmp_path / "m0", tmp_path / "m1", tmp_path / "report.json")

    assert report["partitions"]["test"]["f1"]["delta_m1_minus_m0"] == pytest.approx(0.1)
    assert report["protocol"]["test_used_for_selection"] is False
    assert (tmp_path / "report.json").is_file()
