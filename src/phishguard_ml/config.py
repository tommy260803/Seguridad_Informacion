from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BaselineConfigError(ValueError):
    """Raised when a baseline configuration is invalid."""


@dataclass(frozen=True)
class CandidateConfig:
    name: str
    model: str
    params: dict[str, Any]
    calibration: str


@dataclass(frozen=True)
class BaselineConfig:
    experiment_version: str
    feature_version: str
    feature_profile: str
    seed: int
    thread_limit: int
    calibration_fraction: float
    ece_bins: int
    selection_metric: str
    threshold_objective: str
    candidates: tuple[CandidateConfig, ...]
    source_path: Path
    raw: dict[str, Any]


def load_baseline_config(path: str | Path) -> BaselineConfig:
    source_path = Path(path).resolve()
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineConfigError(f"Cannot read baseline configuration: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise BaselineConfigError("Only baseline schema_version 1 is supported")
    fraction = float(raw.get("calibration_fraction", 0))
    if not 0 < fraction < 1:
        raise BaselineConfigError("calibration_fraction must be between 0 and 1")
    ece_bins = int(raw.get("ece_bins", 0))
    if ece_bins < 2:
        raise BaselineConfigError("ece_bins must be at least 2")
    thread_limit = int(raw.get("thread_limit", 0))
    if thread_limit < 1:
        raise BaselineConfigError("thread_limit must be at least 1")
    if raw.get("selection_metric") != "pr_auc" or raw.get("threshold_objective") != "f1":
        raise BaselineConfigError("This version supports pr_auc selection and f1 thresholding")
    feature_profile = str(raw.get("feature_profile") or "")
    if feature_profile not in {"authority_only", "full_url"}:
        raise BaselineConfigError("feature_profile must be authority_only or full_url")
    candidate_rows = raw.get("candidates")
    if not isinstance(candidate_rows, list) or not candidate_rows:
        raise BaselineConfigError("At least one candidate is required")
    candidates: list[CandidateConfig] = []
    names: set[str] = set()
    for row in candidate_rows:
        if not isinstance(row, dict):
            raise BaselineConfigError("Each candidate must be an object")
        name = str(row.get("name") or "")
        model = str(row.get("model") or "")
        calibration = str(row.get("calibration") or "")
        params = row.get("params")
        if not name or name in names:
            raise BaselineConfigError("Candidate names must be non-empty and unique")
        if model not in {"logistic_regression", "hist_gradient_boosting"}:
            raise BaselineConfigError(f"Unsupported model: {model}")
        if calibration not in {"sigmoid", "isotonic"}:
            raise BaselineConfigError(f"Unsupported calibration: {calibration}")
        if not isinstance(params, dict):
            raise BaselineConfigError("Candidate params must be an object")
        names.add(name)
        candidates.append(CandidateConfig(name, model, params, calibration))
    return BaselineConfig(
        experiment_version=str(raw["experiment_version"]),
        feature_version=str(raw["feature_version"]),
        feature_profile=feature_profile,
        seed=int(raw["seed"]),
        thread_limit=thread_limit,
        calibration_fraction=fraction,
        ece_bins=ece_bins,
        selection_metric="pr_auc",
        threshold_objective="f1",
        candidates=tuple(candidates),
        source_path=source_path,
        raw=raw,
    )
