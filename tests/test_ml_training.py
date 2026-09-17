import csv
import json
from pathlib import Path

from phishguard_ml.config import load_baseline_config
from phishguard_ml.training import DatasetRow, _validation_roles, train_url_baseline


def write_baseline_config(root: Path) -> Path:
    path = root / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "experiment_version": "test-v1",
                "feature_version": "url-features-1.0.0",
                "feature_profile": "full_url",
                "seed": 11,
                "thread_limit": 1,
                "calibration_fraction": 0.5,
                "ece_bins": 5,
                "selection_metric": "pr_auc",
                "threshold_objective": "f1",
                "candidates": [
                    {
                        "name": "logistic",
                        "model": "logistic_regression",
                        "params": {"C": 1.0, "max_iter": 300},
                        "calibration": "sigmoid",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def write_dataset(root: Path) -> Path:
    dataset = root / "dataset"
    (dataset / "splits").mkdir(parents=True)
    samples = []
    assignments = []
    for index in range(160):
        phishing = index % 2 == 1
        label = "phishing" if phishing else "legitimate"
        domain = f"{'secure-login' if phishing else 'site'}-{index}.com"
        url = (
            f"http://{domain}/account/verify/password?session={index}"
            if phishing
            else f"https://{domain}/home"
        )
        partition = "train" if index < 100 else "validation" if index < 130 else "test"
        sample_id = f"sample-{index:03d}"
        samples.append(
            {
                "sample_id": sample_id,
                "canonical_url": url,
                "registered_domain": domain,
                "label": label,
            }
        )
        assignments.append({"sample_id": sample_id, "partition": partition})
    with (dataset / "samples.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["sample_id", "canonical_url", "registered_domain", "label"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(samples)
    with (dataset / "splits" / "conventional.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["sample_id", "partition"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(assignments)
    return dataset


def test_train_url_baseline_writes_auditable_outputs(tmp_path: Path) -> None:
    config = load_baseline_config(write_baseline_config(tmp_path))
    dataset = write_dataset(tmp_path)

    result = train_url_baseline(config, dataset, "conventional", tmp_path / "run")

    metrics = json.loads((result / "metrics.json").read_text(encoding="utf-8"))
    manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
    assert metrics["split"] == "conventional"
    assert metrics["partitions"]["test"]["selected_threshold"]["f1"] == 1.0
    assert manifest["counts"]["partitions"] == {"test": 30, "train": 100, "validation": 30}
    assert {item["path"] for item in manifest["outputs"]} == {
        "candidate-results.json",
        "feature-registry.json",
        "metrics.json",
        "model.joblib",
        "predictions.csv",
    }


def test_feature_cache_is_reused_only_for_same_dataset(tmp_path: Path) -> None:
    config = load_baseline_config(write_baseline_config(tmp_path))
    dataset = write_dataset(tmp_path)
    cache = tmp_path / "cache" / "features.npz"

    first = train_url_baseline(config, dataset, "conventional", tmp_path / "run-a", cache)
    second = train_url_baseline(config, dataset, "conventional", tmp_path / "run-b", cache)

    first_metrics = json.loads((first / "metrics.json").read_text(encoding="utf-8"))
    second_metrics = json.loads((second / "metrics.json").read_text(encoding="utf-8"))
    assert first_metrics["feature_cache_status"] == "miss"
    assert second_metrics["feature_cache_status"] == "hit"
    assert first_metrics["partitions"] == second_metrics["partitions"]


def test_validation_roles_keep_domains_together() -> None:
    rows = [
        DatasetRow(f"sample-{index}", f"https://{domain}/{index}", domain, index % 2, "validation")
        for index, domain in enumerate(["same.com", "same.com", "other.com", "third.com"])
    ]

    roles = _validation_roles(rows, fraction=0.5, seed=3)

    assert roles["sample-0"] == roles["sample-1"]
