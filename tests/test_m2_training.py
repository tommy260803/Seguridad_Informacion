import json
from pathlib import Path

from phishguard_ml.config import load_baseline_config
from phishguard_ml.m2_training import train_m2

from test_m1_training import write_dataset, write_m1_config, write_results


def write_content_results(path: Path) -> Path:
    with path.open("w", encoding="utf-8") as stream:
        for index in range(60):
            phishing = index % 2
            result = {
                "status": "success",
                "features": {
                    "content_available": 1.0,
                    "html_form_count": float(phishing),
                    "html_password_input_count": float(phishing),
                    "html_external_form_action_count": float(phishing),
                    "html_login_term_count": float(phishing),
                },
            }
            stream.write(json.dumps({"sample_id": f"sample-{index}", "result": result}) + "\n")
    return path


def test_m2_training_combines_versioned_feature_families(tmp_path: Path) -> None:
    dataset, seed = write_dataset(tmp_path / "dataset", 20260916)
    config = load_baseline_config(write_m1_config(tmp_path / "m2.json", seed))
    output = train_m2(
        config,
        dataset,
        "conventional",
        write_results(tmp_path / "infra.jsonl"),
        write_content_results(tmp_path / "content.jsonl"),
        tmp_path / "output",
    )

    metrics = json.loads((output / "metrics.json").read_text(encoding="utf-8"))
    registry = json.loads((output / "feature-registry.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert metrics["feature_profile"] == "authority_only_plus_infrastructure_plus_content"
    assert registry["content_feature_version"] == "content-features-1.0.0"
    assert len(registry["active_features"]) == 50
    assert manifest["feature_version"] == "url-features-1.0.0"
    assert (output / "model.joblib").is_file()
