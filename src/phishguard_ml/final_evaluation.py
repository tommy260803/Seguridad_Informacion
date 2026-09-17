from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

METRICS = ("f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error")


class FinalEvaluationError(ValueError):
    pass


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalEvaluationError(f"Invalid artifact: {path}") from exc
    if not isinstance(value, dict):
        raise FinalEvaluationError(f"Artifact must be an object: {path}")
    return value


def evaluate_runs(runs: dict[str, str | Path], output: str | Path | None = None) -> dict[str, Any]:
    if not runs or "M0" not in runs:
        raise FinalEvaluationError("M0 run is required as comparison reference")
    artifacts = {name: (Path(path), _read(Path(path) / "manifest.json"), _read(Path(path) / "metrics.json")) for name, path in runs.items()}
    reference = artifacts["M0"][1]
    split = reference.get("split")
    hashes = reference.get("inputs", {})
    for name, (_path, manifest, _metrics) in artifacts.items():
        if manifest.get("split") != split or manifest.get("inputs", {}).get("samples_csv_sha256") != hashes.get("samples_csv_sha256") or manifest.get("inputs", {}).get("split_csv_sha256") != hashes.get("split_csv_sha256"):
            raise FinalEvaluationError(f"Run {name} does not use the same dataset and split as M0")
    rows = []
    for name, (_path, _manifest, metrics) in artifacts.items():
        values = metrics.get("partitions", {}).get("test", {}).get("selected_threshold")
        if not isinstance(values, dict):
            raise FinalEvaluationError(f"Missing test metrics for {name}")
        row = {"run": name, "split": split, **{metric: float(values[metric]) for metric in METRICS if metric in values}}
        rows.append(row)
    baseline = next(row for row in rows if row["run"] == "M0")
    for row in rows:
        for metric in METRICS:
            if metric in row and metric in baseline:
                row[f"delta_vs_M0_{metric}"] = round(row[metric] - baseline[metric], 12)
    result = {"schema_version": 1, "protocol": {"test_used_for_selection": False, "same_dataset_and_split": True}, "split": split, "runs": rows}
    if output is not None:
        destination = Path(output); destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with destination.with_suffix(".csv").open("w", encoding="utf-8", newline="") as stream:
            fields = sorted({key for row in rows for key in row})
            writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n"); writer.writeheader(); writer.writerows(rows)
    return result
