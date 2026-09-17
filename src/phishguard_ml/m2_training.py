from __future__ import annotations

import csv
import json
import platform
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from threadpoolctl import threadpool_limits

from phishguard_data.hashing import canonical_json, sha256_file, sha256_text
from phishguard_ml import __version__
from phishguard_ml.config import BaselineConfig
from phishguard_ml.content import CONTENT_FEATURE_NAMES, CONTENT_FEATURE_VERSION, content_feature_matrix
from phishguard_ml.evaluation import classification_metrics, select_f1_threshold
from phishguard_ml.features import FEATURE_NAMES, FEATURE_PROFILES, FEATURE_VERSION, UrlFeatureContext, feature_matrix
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, INFRA_FEATURE_VERSION, infrastructure_feature_matrix
from phishguard_ml.training import _fit_candidate, _indices_for, _load_rows, _validation_roles


class M2TrainingError(RuntimeError):
    """Raised when the multimodal M2 training contract cannot be satisfied."""


def train_m2(
    config: BaselineConfig,
    dataset_dir: Path,
    split_name: str,
    infra_results: Path,
    content_results: Path,
    output_dir: Path,
) -> Path:
    if config.feature_version != FEATURE_VERSION or config.feature_profile != "authority_only":
        raise M2TrainingError("M2 requires the authority_only URL feature profile")
    rows = _load_rows(dataset_dir.resolve(), split_name)
    url_matrix = feature_matrix(
        [UrlFeatureContext(row.canonical_url, row.registered_domain) for row in rows]
    )
    url_indices = [FEATURE_NAMES.index(name) for name in FEATURE_PROFILES["authority_only"]]
    sample_ids = [row.sample_id for row in rows]
    matrix = np.concatenate(
        (
            url_matrix[:, url_indices],
            infrastructure_feature_matrix(sample_ids, infra_results),
            content_feature_matrix(sample_ids, content_results),
        ),
        axis=1,
    )
    if not np.isfinite(matrix).all():
        raise M2TrainingError("M2 feature matrix contains non-finite values")
    y = np.asarray([row.label for row in rows], dtype=np.int8)
    roles = _validation_roles(rows, config.calibration_fraction, config.seed)
    train_idx = _indices_for(rows, lambda row: row.partition == "train")
    calibration_idx = _indices_for(rows, lambda row: roles.get(row.sample_id) == "calibration")
    selection_idx = _indices_for(rows, lambda row: roles.get(row.sample_id) == "selection")
    if set(y[calibration_idx]) != {0, 1} or set(y[selection_idx]) != {0, 1}:
        raise M2TrainingError("M2 calibration and selection must each contain both labels")
    best_model: Any = None
    best_candidate: Any = None
    best_key: tuple[float, float, str] | None = None
    candidate_results: list[dict[str, Any]] = []
    for candidate in config.candidates:
        model, fit_seconds = _fit_candidate(
            candidate, config.seed, matrix[train_idx], y[train_idx],
            matrix[calibration_idx], y[calibration_idx], config.thread_limit
        )
        with threadpool_limits(limits=config.thread_limit):
            probability = model.predict_proba(matrix[selection_idx])[:, 1]
        selection_metrics = classification_metrics(y[selection_idx], probability, 0.5, config.ece_bins)
        candidate_results.append({
            "name": candidate.name, "model": candidate.model, "params": candidate.params,
            "calibration": candidate.calibration, "fit_seconds": fit_seconds,
            "selection_metrics_at_0_5": selection_metrics,
        })
        key = (selection_metrics["pr_auc"], -selection_metrics["brier_score"], candidate.name)
        if best_key is None or key > best_key:
            best_key, best_model, best_candidate = key, model, candidate
    if best_model is None or best_candidate is None:
        raise M2TrainingError("No M2 candidate could be selected")
    with threadpool_limits(limits=config.thread_limit):
        selection_probability = best_model.predict_proba(matrix[selection_idx])[:, 1]
    threshold_selection = select_f1_threshold(y[selection_idx], selection_probability)
    threshold = threshold_selection["threshold"]
    metrics: dict[str, Any] = {
        "schema_version": 1, "experiment_version": config.experiment_version,
        "feature_version": FEATURE_VERSION, "infrastructure_feature_version": INFRA_FEATURE_VERSION,
        "content_feature_version": CONTENT_FEATURE_VERSION,
        "feature_profile": "authority_only_plus_infrastructure_plus_content",
        "split": split_name, "selected_candidate": best_candidate.name,
        "threshold_selection": threshold_selection, "partitions": {},
    }
    probabilities = np.empty(len(rows), dtype=np.float64)
    for partition in ("train", "validation", "test"):
        indices = _indices_for(rows, lambda row, expected=partition: row.partition == expected)
        with threadpool_limits(limits=config.thread_limit):
            partition_probability = best_model.predict_proba(matrix[indices])[:, 1]
        probabilities[indices] = partition_probability
        metrics["partitions"][partition] = {
            "selected_threshold": classification_metrics(y[indices], partition_probability, threshold, config.ece_bins),
            "threshold_0_5": classification_metrics(y[indices], partition_probability, 0.5, config.ece_bins),
        }
    destination = output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    for name, value in (("candidate-results.json", candidate_results), ("metrics.json", metrics)):
        (destination / name).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    active_features = list(FEATURE_PROFILES["authority_only"]) + list(INFRA_FEATURE_NAMES) + list(CONTENT_FEATURE_NAMES)
    (destination / "feature-registry.json").write_text(json.dumps({
        "schema_version": 1, "feature_version": FEATURE_VERSION,
        "infrastructure_feature_version": INFRA_FEATURE_VERSION,
        "content_feature_version": CONTENT_FEATURE_VERSION,
        "feature_profile": "authority_only_plus_infrastructure_plus_content",
        "active_features": active_features,
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (destination / "predictions.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["sample_id", "partition", "validation_role", "label", "probability_phishing", "prediction"])
        for index, row in sorted(enumerate(rows), key=lambda item: item[1].sample_id):
            probability = float(probabilities[index])
            writer.writerow([row.sample_id, row.partition, roles.get(row.sample_id, ""), row.label, f"{probability:.17g}", int(probability >= threshold)])
    joblib.dump({"schema_version": 1, "experiment_version": config.experiment_version,
                 "feature_version": FEATURE_VERSION,
                 "infrastructure_feature_version": INFRA_FEATURE_VERSION,
                 "content_feature_version": CONTENT_FEATURE_VERSION,
                 "feature_names": active_features, "candidate": best_candidate,
                 "threshold": threshold, "model": best_model}, destination / "model.joblib", compress=3)
    manifest = {
        "schema_version": 1, "experiment_version": config.experiment_version,
        "pipeline_version": __version__, "feature_version": FEATURE_VERSION,
        "infrastructure_feature_version": INFRA_FEATURE_VERSION,
        "content_feature_version": CONTENT_FEATURE_VERSION,
        "feature_profile": metrics["feature_profile"],
        "split": split_name, "seed": config.seed, "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__, "config_sha256": sha256_text(canonical_json(config.raw)),
        "inputs": {"samples_csv_sha256": sha256_file(dataset_dir / "samples.csv"),
                   "split_csv_sha256": sha256_file(dataset_dir / "splits" / f"{split_name}.csv"),
                   "infrastructure_results_sha256": sha256_file(infra_results),
                   "content_results_sha256": sha256_file(content_results)},
        "counts": {"total": len(rows), "partitions": {p: sum(row.partition == p for row in rows) for p in ("train", "validation", "test")}},
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
