import csv
import json
from pathlib import Path

from phishguard_ml.config import load_baseline_config
from phishguard_ml.m1_training import train_m1
from phishguard_ml.training import DatasetRow, _validation_roles


def write_m1_config(path: Path, seed: int) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "experiment_version": "m1-test-1",
                "feature_version": "url-features-1.0.0",
                "feature_profile": "authority_only",
                "seed": seed,
                "thread_limit": 1,
                "calibration_fraction": 0.5,
                "ece_bins": 5,
                "selection_metric": "pr_auc",
                "threshold_objective": "f1",
                "candidates": [
                    {
                        "name": "logistic",
                        "model": "logistic_regression",
                        "params": {"C": 1.0, "max_iter": 200},
                        "calibration": "sigmoid",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def write_dataset(path: Path, seed: int) -> tuple[Path, int]:
    path.mkdir()
    (path / "splits").mkdir()
    fields = [
        "sample_id",
        "canonical_url",
        "canonical_url_sha256",
        "registered_domain",
        "label",
        "observed_at",
        "url_origin",
    ]
    rows: list[list[str]] = []
    assignments: list[tuple[str, str]] = []
    dataset_rows: list[DatasetRow] = []
    for index in range(60):
        partition = "train" if index < 30 else "validation" if index < 50 else "test"
        label = "phishing" if index % 2 else "legitimate"
        sample_id = f"sample-{index}"
        domain = f"domain-{index}.test"
        url = f"https://{domain}/{'login' if label == 'phishing' else ''}"
        rows.append([sample_id, url, f"hash-{index}", domain, label, "2026-09-16T10:00:00Z", "reported_url"])
        assignments.append((sample_id, partition))
        dataset_rows.append(DatasetRow(sample_id, url, domain, int(label == "phishing"), partition))
    # Pick a deterministic seed whose validation roles each contain both classes.
    assert {dataset_rows[index].label for index in range(30, 50)} == {0, 1}
    while True:
        roles = _validation_roles(dataset_rows, 0.5, seed)
        if all(
            {row.label for row in dataset_rows[30:50] if roles.get(row.sample_id) == role}
            == {0, 1}
            for role in ("calibration", "selection")
        ):
            break
        seed += 1
    with (path / "samples.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(fields)
        writer.writerows(rows)
    with (path / "splits" / "conventional.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["sample_id", "partition"])
        writer.writerows(assignments)
    return path, seed


def write_results(path: Path) -> Path:
    with path.open("w", encoding="utf-8") as stream:
        for index in range(60):
            label = index % 2
            result = {
                "status": "success",
                "features": {
                    "infrastructure_available": 1.0,
                    "dns_address_count_initial": 1.0 + label,
                    "tls_hop_count": 1.0,
                    "certificate_available": 1.0,
                    "final_status_code": 200.0,
                    "final_uses_https": 1.0,
                },
            }
            stream.write(json.dumps({"sample_id": f"sample-{index}", "result": result}) + "\n")
    return path


def test_m1_training_produces_reproducible_artifacts(tmp_path: Path) -> None:
    seed = 20260916
    dataset, seed = write_dataset(tmp_path / "dataset", seed)
    config = load_baseline_config(write_m1_config(tmp_path / "m1.json", seed))
    infra_results = write_results(tmp_path / "results.jsonl")

    output = train_m1(config, dataset, "conventional", infra_results, tmp_path / "output")

    metrics = json.loads((output / "metrics.json").read_text(encoding="utf-8"))
    registry = json.loads((output / "feature-registry.json").read_text(encoding="utf-8"))
    assert metrics["feature_profile"] == "authority_only_plus_infrastructure"
    assert set(metrics["partitions"]) == {"train", "validation", "test"}
    assert registry["infrastructure_feature_version"] == "infra-features-1.0.0"
    assert (output / "model.joblib").is_file()
    assert (output / "predictions.csv").read_text(encoding="utf-8").count("\n") == 61
