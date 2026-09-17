from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from phishguard_ml.content import CONTENT_FEATURE_NAMES, CONTENT_FEATURE_VERSION, content_feature_matrix
from phishguard_ml.features import FEATURE_NAMES, FEATURE_PROFILES, FEATURE_VERSION, UrlFeatureContext, feature_matrix
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, INFRA_FEATURE_VERSION, infrastructure_feature_matrix
from phishguard_ml.m2_training import M2TrainingError
from phishguard_ml.training import _fit_candidate, _indices_for, _load_rows, _validation_roles
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, VISUAL_FEATURE_VERSION, visual_feature_matrix


def train_m3(config: Any, dataset_dir: Path, split_name: str, infra_results: Path,
             content_results: Path, visual_results: Path, output_dir: Path) -> Path:
    if config.feature_version != FEATURE_VERSION or config.feature_profile != "authority_only":
        raise M2TrainingError("M3 requires the authority_only URL feature profile")
    rows = _load_rows(dataset_dir.resolve(), split_name)
    url = feature_matrix([UrlFeatureContext(r.canonical_url, r.registered_domain) for r in rows])
    url_idx = [FEATURE_NAMES.index(n) for n in FEATURE_PROFILES["authority_only"]]
    ids = [r.sample_id for r in rows]
    matrix = np.concatenate((url[:, url_idx], infrastructure_feature_matrix(ids, infra_results),
                             content_feature_matrix(ids, content_results), visual_feature_matrix(ids, visual_results)), axis=1)
    if not np.isfinite(matrix).all():
        raise M2TrainingError("M3 feature matrix contains non-finite values")
    y = np.asarray([r.label for r in rows], dtype=np.int8)
    roles = _validation_roles(rows, config.calibration_fraction, config.seed)
    train_idx = _indices_for(rows, lambda r: r.partition == "train")
    calibration_idx = _indices_for(rows, lambda r: roles.get(r.sample_id) == "calibration")
    selection_idx = _indices_for(rows, lambda r: roles.get(r.sample_id) == "selection")
    if set(y[calibration_idx]) != {0, 1} or set(y[selection_idx]) != {0, 1}:
        raise M2TrainingError("M3 calibration and selection must each contain both labels")
    best_model = None
    best_candidate = None
    best_key = None
    results = []
    for candidate in config.candidates:
        model, fit_seconds = _fit_candidate(candidate, config.seed, matrix[train_idx], y[train_idx], matrix[calibration_idx], y[calibration_idx], config.thread_limit)
        probability = model.predict_proba(matrix[selection_idx])[:, 1]
        from phishguard_ml.evaluation import classification_metrics, select_f1_threshold
        selection = classification_metrics(y[selection_idx], probability, 0.5, config.ece_bins)
        results.append({"name": candidate.name, "model": candidate.model, "params": candidate.params, "calibration": candidate.calibration, "fit_seconds": fit_seconds, "selection_metrics_at_0_5": selection})
        key = (selection["pr_auc"], -selection["brier_score"], candidate.name)
        if best_key is None or key > best_key:
            best_key, best_model, best_candidate = key, model, candidate
    if best_model is None:
        raise M2TrainingError("No M3 candidate could be selected")
    from phishguard_ml.evaluation import classification_metrics, select_f1_threshold
    selection_probability = best_model.predict_proba(matrix[selection_idx])[:, 1]
    threshold_selection = select_f1_threshold(y[selection_idx], selection_probability)
    threshold = threshold_selection["threshold"]
    metrics = {"schema_version": 1, "experiment_version": config.experiment_version, "feature_version": FEATURE_VERSION,
               "infrastructure_feature_version": INFRA_FEATURE_VERSION, "content_feature_version": CONTENT_FEATURE_VERSION,
               "visual_feature_version": VISUAL_FEATURE_VERSION, "feature_profile": "authority_only_plus_infrastructure_plus_content_plus_visual",
               "split": split_name, "selected_candidate": best_candidate.name, "threshold_selection": threshold_selection, "partitions": {}}
    for partition in ("train", "validation", "test"):
        idx = _indices_for(rows, lambda r, p=partition: r.partition == p)
        probability = best_model.predict_proba(matrix[idx])[:, 1]
        metrics["partitions"][partition] = {"selected_threshold": classification_metrics(y[idx], probability, threshold, config.ece_bins), "threshold_0_5": classification_metrics(y[idx], probability, 0.5, config.ece_bins)}
    destination = output_dir.resolve(); destination.mkdir(parents=True, exist_ok=False)
    active = list(FEATURE_PROFILES["authority_only"]) + list(INFRA_FEATURE_NAMES) + list(CONTENT_FEATURE_NAMES) + list(VISUAL_FEATURE_NAMES)
    (destination / "candidate-results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "feature-registry.json").write_text(json.dumps({"schema_version": 1, "feature_version": FEATURE_VERSION, "infrastructure_feature_version": INFRA_FEATURE_VERSION, "content_feature_version": CONTENT_FEATURE_VERSION, "visual_feature_version": VISUAL_FEATURE_VERSION, "feature_profile": metrics["feature_profile"], "active_features": active}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    import joblib
    joblib.dump({"schema_version": 1, "feature_names": active, "threshold": threshold, "model": best_model}, destination / "model.joblib", compress=3)
    return destination
