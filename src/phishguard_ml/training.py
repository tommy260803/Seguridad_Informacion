from __future__ import annotations

import csv
import gc
import json
import platform
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

from phishguard_data.hashing import canonical_json, sha256_file, sha256_text
from phishguard_ml import __version__
from phishguard_ml.config import BaselineConfig, CandidateConfig
from phishguard_ml.evaluation import classification_metrics, select_f1_threshold
from phishguard_ml.features import (
    FEATURE_NAMES,
    FEATURE_PROFILES,
    FEATURE_VERSION,
    UrlFeatureContext,
    feature_matrix,
)


@dataclass(frozen=True)
class DatasetRow:
    sample_id: str
    canonical_url: str
    registered_domain: str
    label: int
    partition: str


class BaselineTrainingError(RuntimeError):
    """Raised when a baseline run violates its data contract."""


def _load_rows(dataset_dir: Path, split_name: str) -> list[DatasetRow]:
    assignments_path = dataset_dir / "splits" / f"{split_name}.csv"
    assignments: dict[str, str] = {}
    try:
        with assignments_path.open("r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                assignments[row["sample_id"]] = row["partition"]
    except OSError as exc:
        raise BaselineTrainingError(f"Cannot read split {split_name}: {exc}") from exc
    if set(assignments.values()) != {"train", "validation", "test"}:
        raise BaselineTrainingError(f"Split {split_name} must contain train, validation and test")
    rows: list[DatasetRow] = []
    seen: set[str] = set()
    with (dataset_dir / "samples.csv").open("r", encoding="utf-8", newline="") as stream:
        for raw in csv.DictReader(stream):
            sample_id = raw["sample_id"]
            partition = assignments.get(sample_id)
            if partition is None:
                continue
            if sample_id in seen:
                raise BaselineTrainingError(f"Duplicate sample_id in samples.csv: {sample_id}")
            seen.add(sample_id)
            label_text = raw["label"]
            if label_text not in {"legitimate", "phishing"}:
                raise BaselineTrainingError(f"Unsupported label: {label_text}")
            rows.append(
                DatasetRow(
                    sample_id=sample_id,
                    canonical_url=raw["canonical_url"],
                    registered_domain=raw["registered_domain"],
                    label=1 if label_text == "phishing" else 0,
                    partition=partition,
                )
            )
    if len(rows) != len(assignments):
        raise BaselineTrainingError("Split references missing samples")
    for partition in ("train", "validation", "test"):
        labels = {row.label for row in rows if row.partition == partition}
        if labels != {0, 1}:
            raise BaselineTrainingError(f"Partition {partition} must contain both labels")
    return rows


def _validation_roles(rows: list[DatasetRow], fraction: float, seed: int) -> dict[str, str]:
    by_domain: dict[str, list[DatasetRow]] = defaultdict(list)
    for row in rows:
        if row.partition == "validation":
            by_domain[row.registered_domain].append(row)
    roles: dict[str, str] = {}
    cutoff = int(fraction * (2**256 - 1))
    for domain, domain_rows in by_domain.items():
        # Domain splits also use a seeded hash; a distinct namespace prevents
        # correlation between the outer split order and this validation role.
        value = int(sha256_text(f"validation-role:{seed}:{domain}"), 16)
        role = "calibration" if value <= cutoff else "selection"
        for row in domain_rows:
            roles[row.sample_id] = role
    return roles


def _make_estimator(candidate: CandidateConfig, seed: int) -> Any:
    if candidate.model == "logistic_regression":
        allowed = {"C", "max_iter"}
        unexpected = set(candidate.params) - allowed
        if unexpected:
            raise BaselineTrainingError(f"Unexpected logistic params: {sorted(unexpected)}")
        classifier = LogisticRegression(
            C=float(candidate.params.get("C", 1.0)),
            max_iter=int(candidate.params.get("max_iter", 1000)),
            solver="liblinear",
            random_state=seed,
        )
        return Pipeline([("scale", StandardScaler()), ("classifier", classifier)])
    allowed = {"max_leaf_nodes", "learning_rate", "max_iter"}
    unexpected = set(candidate.params) - allowed
    if unexpected:
        raise BaselineTrainingError(f"Unexpected hist gradient boosting params: {sorted(unexpected)}")
    return HistGradientBoostingClassifier(
        max_leaf_nodes=int(candidate.params.get("max_leaf_nodes", 31)),
        learning_rate=float(candidate.params.get("learning_rate", 0.1)),
        max_iter=int(candidate.params.get("max_iter", 150)),
        early_stopping=False,
        random_state=seed,
    )


def _fit_candidate(
    candidate: CandidateConfig,
    seed: int,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_calibration: np.ndarray,
    y_calibration: np.ndarray,
    thread_limit: int,
) -> tuple[CalibratedClassifierCV, float]:
    started = time.perf_counter()
    estimator = _make_estimator(candidate, seed)
    with threadpool_limits(limits=thread_limit):
        estimator.fit(x_train, y_train)
        calibrated = CalibratedClassifierCV(FrozenEstimator(estimator), method=candidate.calibration)
        calibrated.fit(x_calibration, y_calibration)
    return calibrated, time.perf_counter() - started


def _git_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def _code_files(root: Path) -> list[dict[str, str]]:
    paths = list((root / "src" / "phishguard_data").glob("*.py"))
    paths.extend((root / "src" / "phishguard_ml").glob("*.py"))
    return [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
        for path in sorted(paths, key=lambda item: item.as_posix())
    ]


def _rows_for(rows: list[DatasetRow], partition: str) -> list[DatasetRow]:
    return [row for row in rows if row.partition == partition]


def _indices_for(rows: list[DatasetRow], predicate: Any) -> np.ndarray:
    return np.asarray([index for index, row in enumerate(rows) if predicate(row)], dtype=np.int64)


def _feature_cache_identity(rows: list[DatasetRow]) -> str:
    return sha256_text("\n".join(row.sample_id for row in rows))


def _load_or_extract_features(
    rows: list[DatasetRow],
    cache_path: Path | None,
) -> tuple[np.ndarray, float, str, str | None]:
    identity = _feature_cache_identity(rows)
    if cache_path and cache_path.is_file():
        started = time.perf_counter()
        with np.load(cache_path, allow_pickle=False) as archive:
            metadata = json.loads(str(archive["metadata"].item()))
            matrix = archive["matrix"]
        if metadata != {
            "feature_version": FEATURE_VERSION,
            "sample_id_hash": identity,
            "samples": len(rows),
            "features": len(FEATURE_NAMES),
        }:
            raise BaselineTrainingError(f"Feature cache identity mismatch: {cache_path}")
        if matrix.shape != (len(rows), len(FEATURE_NAMES)) or not np.isfinite(matrix).all():
            raise BaselineTrainingError(f"Feature cache matrix is invalid: {cache_path}")
        return matrix, time.perf_counter() - started, "hit", sha256_file(cache_path)

    contexts = [UrlFeatureContext(row.canonical_url, row.registered_domain) for row in rows]
    started = time.perf_counter()
    matrix = feature_matrix(contexts)
    elapsed = time.perf_counter() - started
    cache_hash = None
    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = canonical_json(
            {
                "feature_version": FEATURE_VERSION,
                "sample_id_hash": identity,
                "samples": len(rows),
                "features": len(FEATURE_NAMES),
            }
        )
        temporary = cache_path.with_suffix(cache_path.suffix + ".part")
        with temporary.open("wb") as stream:
            np.savez_compressed(stream, matrix=matrix, metadata=np.asarray(metadata))
        temporary.replace(cache_path)
        cache_hash = sha256_file(cache_path)
    return matrix, elapsed, "miss", cache_hash


def train_url_baseline(
    config: BaselineConfig,
    dataset_dir: Path,
    split_name: str,
    output_dir: Path,
    feature_cache: Path | None = None,
) -> Path:
    if config.feature_version != FEATURE_VERSION:
        raise BaselineTrainingError(
            f"Configured feature version {config.feature_version} does not match {FEATURE_VERSION}"
        )
    dataset_dir = dataset_dir.resolve()
    destination = output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    rows = _load_rows(dataset_dir, split_name)
    resolved_cache = feature_cache.resolve() if feature_cache else None
    x, feature_seconds, cache_status, cache_hash = _load_or_extract_features(rows, resolved_cache)
    active_feature_names = FEATURE_PROFILES[config.feature_profile]
    active_indices = [FEATURE_NAMES.index(name) for name in active_feature_names]
    x = x[:, active_indices]
    y = np.asarray([row.label for row in rows], dtype=np.int8)
    roles = _validation_roles(rows, config.calibration_fraction, config.seed)
    train_idx = _indices_for(rows, lambda row: row.partition == "train")
    calibration_idx = _indices_for(rows, lambda row: roles.get(row.sample_id) == "calibration")
    selection_idx = _indices_for(rows, lambda row: roles.get(row.sample_id) == "selection")
    if not len(calibration_idx) or not len(selection_idx):
        raise BaselineTrainingError("Validation is too small to separate calibration and selection")
    if set(y[calibration_idx]) != {0, 1} or set(y[selection_idx]) != {0, 1}:
        raise BaselineTrainingError("Calibration and selection must each contain both labels")

    candidate_results: list[dict[str, Any]] = []
    best_model: CalibratedClassifierCV | None = None
    best_candidate: CandidateConfig | None = None
    best_key: tuple[float, float, str] | None = None
    for candidate in config.candidates:
        model, fit_seconds = _fit_candidate(
            candidate,
            config.seed,
            x[train_idx],
            y[train_idx],
            x[calibration_idx],
            y[calibration_idx],
            config.thread_limit,
        )
        with threadpool_limits(limits=config.thread_limit):
            probability = model.predict_proba(x[selection_idx])[:, 1]
        selection_metrics = classification_metrics(
            y[selection_idx], probability, 0.5, config.ece_bins
        )
        result = {
            "name": candidate.name,
            "model": candidate.model,
            "params": candidate.params,
            "calibration": candidate.calibration,
            "fit_seconds": fit_seconds,
            "selection_metrics_at_0_5": selection_metrics,
        }
        candidate_results.append(result)
        key = (
            selection_metrics["pr_auc"],
            -selection_metrics["brier_score"],
            candidate.name,
        )
        if best_key is None or key > best_key:
            best_key = key
            best_model = model
            best_candidate = candidate
        else:
            del model
            gc.collect()
    if best_model is None or best_candidate is None:
        raise BaselineTrainingError("No candidate could be selected")

    with threadpool_limits(limits=config.thread_limit):
        selection_probability = best_model.predict_proba(x[selection_idx])[:, 1]
    threshold_selection = select_f1_threshold(y[selection_idx], selection_probability)
    threshold = threshold_selection["threshold"]
    metrics: dict[str, Any] = {
        "schema_version": 1,
        "experiment_version": config.experiment_version,
        "feature_version": config.feature_version,
        "feature_profile": config.feature_profile,
        "split": split_name,
        "selected_candidate": best_candidate.name,
        "threshold_selection": threshold_selection,
        "feature_extraction_seconds": feature_seconds,
        "feature_cache_status": cache_status,
        "partitions": {},
    }
    probabilities = np.empty(len(rows), dtype=np.float64)
    for partition in ("train", "validation", "test"):
        indices = _indices_for(rows, lambda row, expected=partition: row.partition == expected)
        with threadpool_limits(limits=config.thread_limit):
            partition_probability = best_model.predict_proba(x[indices])[:, 1]
        probabilities[indices] = partition_probability
        metrics["partitions"][partition] = {
            "selected_threshold": classification_metrics(
                y[indices], partition_probability, threshold, config.ece_bins
            ),
            "threshold_0_5": classification_metrics(
                y[indices], partition_probability, 0.5, config.ece_bins
            ),
        }

    candidates_path = destination / "candidate-results.json"
    candidates_path.write_text(
        json.dumps(candidate_results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metrics_path = destination / "metrics.json"
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    registry_path = destination / "feature-registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "feature_version": FEATURE_VERSION,
                "feature_profile": config.feature_profile,
                "active_features": list(active_feature_names),
                "all_extracted_features": list(FEATURE_NAMES),
                "suspicious_token_feature": "fixed lexicon declared in source code",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    predictions_path = destination / "predictions.csv"
    with predictions_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            ["sample_id", "partition", "validation_role", "label", "probability_phishing", "prediction"]
        )
        for index, row in sorted(enumerate(rows), key=lambda item: item[1].sample_id):
            probability = float(probabilities[index])
            writer.writerow(
                [
                    row.sample_id,
                    row.partition,
                    roles.get(row.sample_id, ""),
                    row.label,
                    f"{probability:.17g}",
                    int(probability >= threshold),
                ]
            )
    model_path = destination / "model.joblib"
    joblib.dump(
        {
            "schema_version": 1,
            "experiment_version": config.experiment_version,
            "feature_version": FEATURE_VERSION,
            "feature_profile": config.feature_profile,
            "feature_names": active_feature_names,
            "candidate": best_candidate,
            "threshold": threshold,
            "model": best_model,
        },
        model_path,
        compress=3,
    )
    output_paths = [candidates_path, metrics_path, registry_path, predictions_path, model_path]
    root = config.source_path.parent.parent
    manifest = {
        "schema_version": 1,
        "experiment_version": config.experiment_version,
        "pipeline_version": __version__,
        "feature_version": FEATURE_VERSION,
        "feature_profile": config.feature_profile,
        "split": split_name,
        "seed": config.seed,
        "thread_limit": config.thread_limit,
        "git_commit": _git_commit(root),
        "code_files": _code_files(root),
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "scikit_learn_version": sklearn.__version__,
        "config_sha256": sha256_text(canonical_json(config.raw)),
        "inputs": {
            "samples_csv_sha256": sha256_file(dataset_dir / "samples.csv"),
            "split_csv_sha256": sha256_file(dataset_dir / "splits" / f"{split_name}.csv"),
            "feature_cache_sha256": cache_hash,
        },
        "outputs": [
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(output_paths, key=lambda item: item.name)
        ],
        "counts": {
            "total": len(rows),
            "partitions": dict(sorted(Counter(row.partition for row in rows).items())),
            "validation_roles": dict(sorted(Counter(roles.values()).items())),
        },
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination
