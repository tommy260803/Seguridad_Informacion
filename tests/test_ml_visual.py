import json
from pathlib import Path

import pytest

from phishguard_ml.visual import VISUAL_FEATURE_NAMES, visual_feature_matrix


def test_visual_feature_matrix_preserves_missing_observation(tmp_path: Path) -> None:
    path = tmp_path / "visual.jsonl"
    path.write_text(json.dumps({"sample_id": "a", "result": {"status": "blocked", "features": {}}}) + "\n", encoding="utf-8")
    matrix = visual_feature_matrix(["a", "missing"], path)
    assert matrix.shape == (2, len(VISUAL_FEATURE_NAMES))
    assert matrix[0, 0] == 0.0
    assert matrix[1].sum() == 0.0


def test_visual_feature_matrix_rejects_non_numeric_values(tmp_path: Path) -> None:
    path = tmp_path / "visual.jsonl"
    path.write_text(json.dumps({"sample_id": "a", "result": {"status": "success", "features": {"visual_width": "wide"}}}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        visual_feature_matrix(["a"], path)
