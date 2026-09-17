import json
from pathlib import Path

import pytest

from phishguard_ml.final_evaluation import FinalEvaluationError, evaluate_runs


def _run(path: Path, split_hash: str, f1: float) -> None:
    path.mkdir()
    (path / "manifest.json").write_text(json.dumps({"split": "conventional", "inputs": {"samples_csv_sha256": "samples", "split_csv_sha256": split_hash}}), encoding="utf-8")
    (path / "metrics.json").write_text(json.dumps({"partitions": {"test": {"selected_threshold": {"f1": f1, "recall": 0.8, "precision": 0.8}}}}), encoding="utf-8")


def test_final_evaluation_exports_comparable_json_and_csv(tmp_path: Path) -> None:
    _run(tmp_path / "m0", "split", 0.5); _run(tmp_path / "m1", "split", 0.7)
    result = evaluate_runs({"M0": tmp_path / "m0", "M1": tmp_path / "m1"}, tmp_path / "report.json")
    assert result["runs"][1]["delta_vs_M0_f1"] == 0.2
    assert (tmp_path / "report.csv").is_file()


def test_final_evaluation_rejects_mismatched_split_hash(tmp_path: Path) -> None:
    _run(tmp_path / "m0", "split-a", 0.5); _run(tmp_path / "m1", "split-b", 0.7)
    with pytest.raises(FinalEvaluationError):
        evaluate_runs({"M0": tmp_path / "m0", "M1": tmp_path / "m1"})
