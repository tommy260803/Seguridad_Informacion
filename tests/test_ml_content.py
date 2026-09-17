import json
from pathlib import Path

import numpy as np
import pytest

from phishguard_ml.content import (
    CONTENT_FEATURE_NAMES,
    ContentFeatureError,
    content_feature_matrix,
    extract_content_features,
    load_content_results,
)


def result(status: str = "success") -> dict[str, object]:
    return {
        "status": status,
        "features": {
            "content_truncated": 0,
            "content_bytes": 100,
            "html_form_count": 1,
            "html_password_input_count": 1,
            "html_external_link_count": 2,
        },
    }


def test_content_registry_is_fixed_and_status_aware() -> None:
    features = extract_content_features(result())

    assert tuple(features) == CONTENT_FEATURE_NAMES
    assert features["content_observation_available"] == 1.0
    assert features["content_status_success"] == 1.0
    assert features["html_password_input_count"] == 1.0
    assert all(np.isfinite(value) for value in features.values())


@pytest.mark.parametrize("status", ["blocked", "error"])
def test_failed_content_does_not_claim_observation(status: str) -> None:
    features = extract_content_features({"status": status, "features": {}})

    assert features["content_observation_available"] == 0.0
    assert features[f"content_status_{status}"] == 1.0


def test_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    path = tmp_path / "content.jsonl"
    row = {"sample_id": "x", "result": result()}
    path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(ContentFeatureError, match="duplicate"):
        load_content_results(path)


def test_matrix_keeps_missing_rows_explicit(tmp_path: Path) -> None:
    path = tmp_path / "content.jsonl"
    path.write_text(json.dumps({"sample_id": "b", "result": result()}) + "\n", encoding="utf-8")

    matrix = content_feature_matrix(["a", "b"], path)

    assert matrix.shape == (2, len(CONTENT_FEATURE_NAMES))
    assert matrix[0, 0] == 0.0
    assert matrix[1, 0] == 1.0
