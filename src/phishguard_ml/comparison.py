from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ComparisonError(ValueError):
    """Raised when M0 and M1 artifacts are not comparable."""


METRICS = ("f1", "recall", "precision", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"Cannot read artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComparisonError(f"Artifact is not an object: {path}")
    return value


def compare_m0_m1(m0_dir: str | Path, m1_dir: str | Path, output: str | Path | None = None) -> dict[str, Any]:
    m0_path, m1_path = Path(m0_dir), Path(m1_dir)
    m0_manifest = _read_json(m0_path / "manifest.json")
    m1_manifest = _read_json(m1_path / "manifest.json")
    m0_metrics = _read_json(m0_path / "metrics.json")
    m1_metrics = _read_json(m1_path / "metrics.json")
    if m0_manifest.get("split") != m1_manifest.get("split"):
        raise ComparisonError("M0 and M1 use different splits")
    if m0_manifest.get("inputs", {}).get("samples_csv_sha256") != m1_manifest.get("inputs", {}).get("samples_csv_sha256"):
        raise ComparisonError("M0 and M1 use different samples.csv inputs")
    if m0_manifest.get("inputs", {}).get("split_csv_sha256") != m1_manifest.get("inputs", {}).get("split_csv_sha256"):
        raise ComparisonError("M0 and M1 use different split inputs")
    partitions = ("train", "validation", "test")
    result: dict[str, Any] = {
        "schema_version": 1,
        "m0_experiment": m0_manifest.get("experiment_version"),
        "m1_experiment": m1_manifest.get("experiment_version"),
        "split": m0_manifest.get("split"),
        "partitions": {},
        "protocol": {
            "same_samples": True,
            "same_split": True,
            "test_used_for_selection": False,
            "note": "Selection metrics and threshold are read from validation artifacts only",
        },
    }
    for partition in partitions:
        m0_values = m0_metrics.get("partitions", {}).get(partition)
        m1_values = m1_metrics.get("partitions", {}).get(partition)
        if not isinstance(m0_values, dict) or not isinstance(m1_values, dict):
            raise ComparisonError(f"Missing partition metrics: {partition}")
        m0_selected = m0_values.get("selected_threshold", {})
        m1_selected = m1_values.get("selected_threshold", {})
        result["partitions"][partition] = {
            metric: {
                "m0": float(m0_selected[metric]),
                "m1": float(m1_selected[metric]),
                "delta_m1_minus_m0": float(m1_selected[metric]) - float(m0_selected[metric]),
            }
            for metric in METRICS
            if metric in m0_selected and metric in m1_selected
        }
    if output is not None:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result
