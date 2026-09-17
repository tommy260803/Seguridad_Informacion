from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np


CONTENT_FEATURE_VERSION = "content-features-1.0.0"

CONTENT_FEATURE_NAMES = (
    "content_observation_available",
    "content_status_success",
    "content_status_blocked",
    "content_status_error",
    "content_truncated",
    "content_bytes",
    "html_tag_count",
    "html_title_length",
    "html_text_length",
    "html_form_count",
    "html_password_input_count",
    "html_email_input_count",
    "html_payment_input_count",
    "html_script_count",
    "html_iframe_count",
    "html_link_count",
    "html_external_link_count",
    "html_external_resource_count",
    "html_external_form_action_count",
    "html_login_term_count",
    "html_payment_term_count",
)


class ContentFeatureError(ValueError):
    """Raised when captured content cannot be mapped to a safe feature vector."""


def _empty() -> dict[str, float]:
    return {name: 0.0 for name in CONTENT_FEATURE_NAMES}


def extract_content_features(result: dict[str, Any] | None) -> dict[str, float]:
    features = _empty()
    if result is None:
        return features
    status = result.get("status")
    if status not in {"success", "blocked", "error"}:
        raise ContentFeatureError(f"Unsupported content status: {status!r}")
    features[f"content_status_{status}"] = 1.0
    features["content_observation_available"] = float(status == "success")
    raw = result.get("features")
    if not isinstance(raw, dict):
        if status == "success":
            raise ContentFeatureError("Successful content result is missing features")
        return features
    for name in CONTENT_FEATURE_NAMES:
        if not name.startswith("html_") and name not in {"content_truncated", "content_bytes"}:
            continue
        value = raw.get(name)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not np.isfinite(value):
            raise ContentFeatureError(f"Content feature {name} is not finite numeric data")
        features[name] = float(value)
    return features


def load_content_results(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ContentFeatureError(f"Cannot read content results: {exc}") from exc
    results: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
            sample_id = row["sample_id"]
            result = row["result"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ContentFeatureError(f"Invalid content result line {line_number}") from exc
        if not isinstance(sample_id, str) or not sample_id or sample_id in results:
            raise ContentFeatureError(f"Invalid or duplicate sample_id at line {line_number}")
        if not isinstance(result, dict):
            raise ContentFeatureError(f"Content result at line {line_number} is not an object")
        extract_content_features(result)
        results[sample_id] = result
    return results


def content_feature_matrix(sample_ids: list[str], results_path: str | Path | None) -> np.ndarray:
    results = load_content_results(results_path) if results_path else {}
    matrix = np.asarray(
        [[extract_content_features(results.get(sample_id))[name] for name in CONTENT_FEATURE_NAMES] for sample_id in sample_ids],
        dtype=np.float64,
    )
    if matrix.shape != (len(sample_ids), len(CONTENT_FEATURE_NAMES)) or not np.isfinite(matrix).all():
        raise ContentFeatureError("Content feature matrix is invalid")
    return matrix
