from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

VISUAL_FEATURE_VERSION = "visual-features-1.0.0"
VISUAL_FEATURE_NAMES = (
    "visual_observation_available", "visual_width", "visual_height", "visual_aspect_ratio",
    "visual_mean_luminance", "visual_luminance_std", "visual_edge_density",
    "visual_dark_pixel_ratio", "visual_saturated_pixel_ratio",
)


def extract_visual_features(result: dict[str, Any] | None) -> dict[str, float]:
    values = {name: 0.0 for name in VISUAL_FEATURE_NAMES}
    if result is None:
        return values
    status = result.get("status")
    if status not in {"success", "blocked", "error"}:
        raise ValueError(f"Unsupported visual status: {status!r}")
    values["visual_observation_available"] = float(status == "success")
    raw = result.get("features") or {}
    if not isinstance(raw, dict):
        raise ValueError("Visual features must be an object")
    for name in VISUAL_FEATURE_NAMES[1:]:
        if name in raw:
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not np.isfinite(value):
                raise ValueError(f"Visual feature {name} is not finite numeric data")
            values[name] = float(value)
    return values


def load_visual_results(path: str | Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
            sample_id, result = row["sample_id"], row["result"]
            if not isinstance(sample_id, str) or not sample_id or sample_id in results or not isinstance(result, dict):
                raise ValueError
            extract_visual_features(result)
            results[sample_id] = result
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid visual result line {line_number}") from exc
    return results


def visual_feature_matrix(sample_ids: list[str], results_path: str | Path | None) -> np.ndarray:
    results = load_visual_results(results_path) if results_path else {}
    matrix = np.asarray([[extract_visual_features(results.get(sample_id))[name] for name in VISUAL_FEATURE_NAMES] for sample_id in sample_ids], dtype=np.float64)
    if matrix.shape != (len(sample_ids), len(VISUAL_FEATURE_NAMES)) or not np.isfinite(matrix).all():
        raise ValueError("Visual feature matrix is invalid")
    return matrix
