from __future__ import annotations

import csv
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from phishguard_data.hashing import canonical_json, sha256_file, sha256_text
from phishguard_infra.analyzer import InfrastructureAnalyzer


class PilotConfigError(ValueError):
    """Raised when a pilot configuration or existing run is invalid."""


@dataclass(frozen=True)
class PilotConfig:
    pilot_version: str
    split: str
    sample_size: int
    seed: int
    partitions: tuple[str, ...]
    labels: tuple[str, ...]
    url_origins: tuple[str, ...]
    max_per_registered_domain: int
    delay_seconds: float
    source_path: Path
    raw: dict[str, Any]


@dataclass(frozen=True)
class PilotSample:
    sample_id: str
    canonical_url: str
    canonical_url_sha256: str
    registered_domain: str
    label: str
    partition: str
    observed_at: str
    url_origin: str

    @property
    def stratum(self) -> tuple[str, str, str]:
        return self.partition, self.label, self.url_origin


def load_pilot_config(path: str | Path) -> PilotConfig:
    source_path = Path(path).resolve()
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PilotConfigError(f"Cannot read pilot configuration: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise PilotConfigError("Only schema_version 1 is supported")
    version = raw.get("pilot_version")
    if not isinstance(version, str) or not version.strip():
        raise PilotConfigError("pilot_version must be a non-empty string")
    split = raw.get("split")
    if not isinstance(split, str) or not split.strip():
        raise PilotConfigError("split must be a non-empty string")
    integer_fields = ("sample_size", "seed", "max_per_registered_domain")
    if any(not isinstance(raw.get(name), int) or isinstance(raw.get(name), bool) for name in integer_fields):
        raise PilotConfigError("Sample size, seed and domain limit must be integers")
    if raw["sample_size"] <= 0 or raw["max_per_registered_domain"] <= 0:
        raise PilotConfigError("Sample size and domain limit must be positive")
    delay = raw.get("delay_seconds")
    if not isinstance(delay, (int, float)) or isinstance(delay, bool) or delay < 0:
        raise PilotConfigError("delay_seconds must be a non-negative number")

    def string_tuple(name: str, allowed: set[str]) -> tuple[str, ...]:
        value = raw.get(name)
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(item, str) or item not in allowed for item in value)
            or len(set(value)) != len(value)
        ):
            raise PilotConfigError(f"{name} contains unsupported or duplicate values")
        return tuple(value)

    partitions = string_tuple("partitions", {"train", "validation"})
    labels = string_tuple("labels", {"legitimate", "phishing"})
    origins = string_tuple("url_origins", {"reported_url", "constructed_from_domain"})
    return PilotConfig(
        pilot_version=version.strip(),
        split=split.strip(),
        sample_size=raw["sample_size"],
        seed=raw["seed"],
        partitions=partitions,
        labels=labels,
        url_origins=origins,
        max_per_registered_domain=raw["max_per_registered_domain"],
        delay_seconds=float(delay),
        source_path=source_path,
        raw=raw,
    )


def _load_assignments(path: Path) -> dict[str, str]:
    assignments: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                sample_id = row["sample_id"]
                if sample_id in assignments:
                    raise PilotConfigError(f"Duplicate sample_id in split: {sample_id}")
                assignments[sample_id] = row["partition"]
    except OSError as exc:
        raise PilotConfigError(f"Cannot read split: {exc}") from exc
    return assignments


def select_pilot(config: PilotConfig, dataset_dir: Path) -> list[PilotSample]:
    dataset_dir = dataset_dir.resolve()
    assignments = _load_assignments(dataset_dir / "splits" / f"{config.split}.csv")
    strata: dict[tuple[str, str, str], list[tuple[str, PilotSample]]] = defaultdict(list)
    with (dataset_dir / "samples.csv").open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            partition = assignments.get(row["sample_id"])
            if (
                partition not in config.partitions
                or row["label"] not in config.labels
                or row["url_origin"] not in config.url_origins
            ):
                continue
            sample = PilotSample(
                sample_id=row["sample_id"],
                canonical_url=row["canonical_url"],
                canonical_url_sha256=row["canonical_url_sha256"],
                registered_domain=row["registered_domain"],
                label=row["label"],
                partition=partition,
                observed_at=row["observed_at"],
                url_origin=row["url_origin"],
            )
            key = sha256_text(f"pilot:{config.seed}:{sample.sample_id}")
            strata[sample.stratum].append((key, sample))
    for values in strata.values():
        values.sort(key=lambda item: (item[0], item[1].sample_id))
    selected: list[PilotSample] = []
    domain_counts: Counter[str] = Counter()
    positions = {key: 0 for key in strata}
    ordered_strata = sorted(strata)
    while len(selected) < config.sample_size:
        made_progress = False
        for stratum in ordered_strata:
            candidates = strata[stratum]
            while positions[stratum] < len(candidates):
                candidate = candidates[positions[stratum]][1]
                positions[stratum] += 1
                if domain_counts[candidate.registered_domain] >= config.max_per_registered_domain:
                    continue
                selected.append(candidate)
                domain_counts[candidate.registered_domain] += 1
                made_progress = True
                break
            if len(selected) >= config.sample_size:
                break
        if not made_progress:
            break
    if len(selected) < config.sample_size:
        raise PilotConfigError(
            f"Only {len(selected)} eligible samples remain after stratification and domain limits"
        )
    return selected


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".part")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _plan_rows(samples: Iterable[PilotSample]) -> list[dict[str, Any]]:
    return [asdict(sample) for sample in samples]


def prepare_pilot(
    config: PilotConfig, dataset_dir: Path, output_dir: Path
) -> tuple[list[PilotSample], dict[str, Any]]:
    dataset_dir = dataset_dir.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    samples_path = dataset_dir / "samples.csv"
    split_path = dataset_dir / "splits" / f"{config.split}.csv"
    identity = {
        "schema_version": 1,
        "pilot_version": config.pilot_version,
        "config_sha256": sha256_text(canonical_json(config.raw)),
        "samples_csv_sha256": sha256_file(samples_path),
        "split_csv_sha256": sha256_file(split_path),
    }
    identity_path = output_dir / "run-identity.json"
    if identity_path.exists():
        existing = json.loads(identity_path.read_text(encoding="utf-8"))
        if existing != identity:
            raise PilotConfigError("Existing pilot output has a different run identity")
    else:
        _write_json(identity_path, identity)
    samples = select_pilot(config, dataset_dir)
    plan_path = output_dir / "plan.jsonl"
    plan_text = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        for row in _plan_rows(samples)
    )
    if plan_path.exists() and plan_path.read_text(encoding="utf-8") != plan_text:
        raise PilotConfigError("Existing pilot plan differs from deterministic selection")
    if not plan_path.exists():
        plan_path.write_text(plan_text, encoding="utf-8")
    summary = {
        "schema_version": 1,
        "pilot_version": config.pilot_version,
        "selected": len(samples),
        "split": config.split,
        "strata": dict(sorted(Counter("/".join(row.stratum) for row in samples).items())),
        "unique_registered_domains": len({row.registered_domain for row in samples}),
        "plan_sha256": sha256_file(plan_path),
    }
    _write_json(output_dir / "plan-summary.json", summary)
    return samples, summary


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def _load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            row = json.loads(line)
            sample_id = row["sample_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PilotConfigError(f"Invalid results line {line_number}") from exc
        if sample_id in seen:
            raise PilotConfigError(f"Duplicate result for sample_id {sample_id}")
        seen.add(sample_id)
        results.append(row)
    return results


def _report(selected: list[PilotSample], results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(row["result"]["status"] for row in results)
    error_codes = Counter(
        row["result"]["error_code"]
        for row in results
        if row["result"].get("error_code") is not None
    )
    latencies = [float(row["result"]["total_elapsed_ms"]) for row in results]
    successful = statuses.get("success", 0)
    return {
        "schema_version": 1,
        "selected": len(selected),
        "attempted": len(results),
        "remaining": len(selected) - len(results),
        "status_counts": dict(sorted(statuses.items())),
        "error_code_counts": dict(sorted(error_codes.items())),
        "infrastructure_coverage": successful / len(results) if results else None,
        "latency_ms": {
            "mean": sum(latencies) / len(latencies) if latencies else None,
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": max(latencies) if latencies else None,
        },
        "attempted_strata": dict(
            sorted(
                Counter(
                    "/".join((row["partition"], row["label"], row["url_origin"]))
                    for row in results
                ).items()
            )
        ),
    }


def run_pilot(
    config: PilotConfig,
    dataset_dir: Path,
    output_dir: Path,
    analyzer: InfrastructureAnalyzer,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    selected, _ = prepare_pilot(config, dataset_dir, output_dir)
    output_dir = output_dir.resolve()
    results_path = output_dir / "results.jsonl"
    results = _load_results(results_path)
    selected_ids = {sample.sample_id for sample in selected}
    if any(row["sample_id"] not in selected_ids for row in results):
        raise PilotConfigError("Existing results contain a sample outside this plan")
    completed = {row["sample_id"] for row in results}
    pending = [sample for sample in selected if sample.sample_id not in completed]
    with results_path.open("a", encoding="utf-8", newline="") as stream:
        for index, sample in enumerate(pending):
            result = analyzer.analyze(sample.canonical_url)
            observed = _parse_utc(result.observed_at)
            label_observed = _parse_utc(sample.observed_at)
            row = {
                "sample_id": sample.sample_id,
                "partition": sample.partition,
                "label": sample.label,
                "url_origin": sample.url_origin,
                "label_observed_at": sample.observed_at,
                "acquisition_lag_seconds": (observed - label_observed).total_seconds(),
                "result": result.to_dict(),
            }
            stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            results.append(row)
            _write_json(output_dir / "report.json", _report(selected, results))
            if index + 1 < len(pending) and config.delay_seconds:
                sleep(config.delay_seconds)
    report = _report(selected, results)
    _write_json(output_dir / "report.json", report)
    return report
