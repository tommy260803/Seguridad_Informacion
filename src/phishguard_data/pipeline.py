from __future__ import annotations

import csv
import json
import platform
import subprocess
from collections import Counter, defaultdict
from dataclasses import fields
from pathlib import Path
from typing import Any, Iterable

from phishguard_data import __version__
from phishguard_data.config import PipelineConfig
from phishguard_data.hashing import canonical_json, sha256_file, sha256_text
from phishguard_data.models import Sample, SourceRecord
from phishguard_data.psl import PublicSuffixList
from phishguard_data.readers import normalize_timestamp, read_phishtank, read_tranco
from phishguard_data.splits import (
    PARTITIONS,
    conventional_split,
    host_unseen_split,
    leakage_audit,
    temporal_host_unseen,
    temporal_split,
)
from phishguard_data.urls import UrlValidationError, canonicalize_url


class DatasetBuildError(RuntimeError):
    """Raised when an input snapshot cannot produce an auditable dataset."""


def _load_snapshot_manifest(snapshot_dir: Path) -> dict[str, Any]:
    path = snapshot_dir / "acquisition-manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetBuildError(f"Invalid or missing acquisition manifest in {snapshot_dir}: {exc}") from exc
    if manifest.get("schema_version") != 1:
        raise DatasetBuildError(f"Unsupported acquisition manifest in {snapshot_dir}")
    observed_at = normalize_timestamp(str(manifest.get("observed_at") or ""))
    if not observed_at:
        raise DatasetBuildError(f"Snapshot has no valid observed_at: {snapshot_dir}")
    manifest["observed_at"] = observed_at
    manifest["snapshot_id"] = str(manifest.get("snapshot_id") or snapshot_dir.name)
    return manifest


def _verify_snapshot_files(snapshot_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records = manifest.get("sources")
    if not isinstance(records, list):
        raise DatasetBuildError(f"Snapshot source records are missing: {snapshot_dir}")
    verified: list[dict[str, Any]] = []
    for raw_record in records:
        if not isinstance(raw_record, dict) or not raw_record.get("filename"):
            raise DatasetBuildError(f"Malformed source record in {snapshot_dir}")
        path = snapshot_dir / str(raw_record["filename"])
        if not path.is_file():
            raise DatasetBuildError(f"Snapshot file is missing: {path}")
        actual_hash = sha256_file(path)
        expected_hash = raw_record.get("sha256")
        if expected_hash and expected_hash != actual_hash:
            raise DatasetBuildError(f"Snapshot hash mismatch: {path}")
        verified.append(
            {
                "name": str(raw_record.get("name") or "unknown"),
                "filename": path.name,
                "sha256": actual_hash,
                "bytes": path.stat().st_size,
            }
        )
    return verified


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


def _code_files(root: Path) -> list[dict[str, Any]]:
    source_root = root / "src" / "phishguard_data"
    if not source_root.is_dir():
        return []
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted(source_root.glob("*.py"), key=lambda item: item.as_posix())
    ]


def _records_for_snapshot(
    snapshot_dir: Path,
    manifest: dict[str, Any],
    config: PipelineConfig,
) -> Iterable[SourceRecord]:
    observed_at = manifest["observed_at"]
    yield from read_phishtank(snapshot_dir / config.build.phishtank_filename, observed_at)
    yield from read_tranco(
        snapshot_dir / config.build.tranco_filename,
        observed_at,
        config.build.tranco_limit,
    )


def _make_samples(
    snapshot_rows: list[tuple[Path, dict[str, Any]]],
    psl: PublicSuffixList,
    config: PipelineConfig,
) -> tuple[list[Sample], dict[str, int], dict[str, Any]]:
    exclusions: Counter[str] = Counter()
    candidates: dict[str, list[Sample]] = defaultdict(list)
    raw_counts: Counter[str] = Counter()

    for snapshot_dir, manifest in snapshot_rows:
        snapshot_id = manifest["snapshot_id"]
        for record in _records_for_snapshot(snapshot_dir, manifest, config):
            raw_counts[record.source] += 1
            try:
                canonical = canonicalize_url(
                    record.raw_url,
                    psl,
                    config.build.allowed_schemes,
                    config.build.max_url_length,
                )
            except UrlValidationError as exc:
                exclusions[f"invalid_url:{exc}"] += 1
                continue
            url_hash = sha256_text(canonical.value)
            sample_id = sha256_text(f"{record.label}\0{canonical.value}")
            candidates[url_hash].append(
                Sample(
                    sample_id=sample_id,
                    canonical_url=canonical.value,
                    canonical_url_sha256=url_hash,
                    label=record.label,
                    source=record.source,
                    source_record_id=record.source_record_id,
                    source_timestamp=record.source_timestamp,
                    observed_at=record.observed_at,
                    first_observed_at=record.observed_at,
                    scheme=canonical.scheme,
                    host=canonical.host,
                    registered_domain=canonical.registered_domain,
                    has_userinfo=canonical.has_userinfo,
                    target=record.target,
                    rank=record.rank,
                    url_origin=record.url_origin,
                    snapshot_id=snapshot_id,
                )
            )

    samples: list[Sample] = []
    duplicate_count = 0
    conflicting_count = 0
    for grouped in candidates.values():
        labels = {sample.label for sample in grouped}
        if len(labels) > 1:
            conflicting_count += len(grouped)
            exclusions["conflicting_label"] += len(grouped)
            continue
        chosen = min(grouped, key=lambda sample: (sample.observed_at, sample.source, sample.source_record_id))
        samples.append(chosen)
        duplicate_count += len(grouped) - 1
    exclusions["duplicate_same_label"] += duplicate_count
    samples.sort(key=lambda sample: sample.sample_id)
    diagnostics = {
        "raw_records_by_source": dict(sorted(raw_counts.items())),
        "candidate_url_hashes": len(candidates),
        "conflicting_records": conflicting_count,
    }
    return samples, dict(sorted(exclusions.items())), diagnostics


def _write_samples(samples: list[Sample], output_dir: Path) -> list[Path]:
    jsonl_path = output_dir / "samples.jsonl"
    csv_path = output_dir / "samples.csv"
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as stream:
        for sample in samples:
            stream.write(canonical_json(sample.to_dict()) + "\n")
    field_names = [field.name for field in fields(Sample)]
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=field_names, lineterminator="\n")
        writer.writeheader()
        for sample in samples:
            writer.writerow(sample.to_dict())
    return [jsonl_path, csv_path]


def _write_assignments(name: str, assignments: dict[str, str], output_dir: Path) -> Path:
    split_dir = output_dir / "splits"
    split_dir.mkdir(exist_ok=True)
    path = split_dir / f"{name}.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["sample_id", "partition"])
        for sample_id, partition in sorted(assignments.items()):
            writer.writerow([sample_id, partition])
    return path


def _split_summary(samples: list[Sample], assignments: dict[str, str]) -> dict[str, Any]:
    by_id = {sample.sample_id: sample for sample in samples}
    partitions: dict[str, Any] = {}
    for partition in PARTITIONS:
        selected = [by_id[sample_id] for sample_id, value in assignments.items() if value == partition]
        partitions[partition] = {
            "samples": len(selected),
            "labels": dict(sorted(Counter(sample.label for sample in selected).items())),
            "unique_hosts": len({sample.host for sample in selected}),
            "unique_registered_domains": len({sample.registered_domain for sample in selected}),
            "observed_at_min": min((sample.observed_at for sample in selected), default=None),
            "observed_at_max": max((sample.observed_at for sample in selected), default=None),
        }
    return {"partitions": partitions, "leakage_audit": leakage_audit(samples, assignments)}


def build_dataset(
    config: PipelineConfig,
    snapshot_dirs: list[Path],
    output_dir: Path | None = None,
) -> Path:
    if not snapshot_dirs:
        raise DatasetBuildError("At least one snapshot is required")
    resolved_snapshots = sorted({path.resolve() for path in snapshot_dirs}, key=lambda path: str(path))
    snapshot_rows: list[tuple[Path, dict[str, Any]]] = []
    input_files: list[dict[str, Any]] = []
    for snapshot_dir in resolved_snapshots:
        manifest = _load_snapshot_manifest(snapshot_dir)
        verified = _verify_snapshot_files(snapshot_dir, manifest)
        expected = {
            config.build.phishtank_filename,
            config.build.tranco_filename,
            config.build.public_suffix_list_filename,
        }
        available = {record["filename"] for record in verified}
        if not expected <= available:
            raise DatasetBuildError(f"Snapshot {snapshot_dir} lacks configured inputs: {sorted(expected - available)}")
        snapshot_rows.append((snapshot_dir, manifest))
        for record in verified:
            input_files.append({"snapshot_id": manifest["snapshot_id"], **record})

    snapshot_rows.sort(key=lambda item: (item[1]["observed_at"], item[1]["snapshot_id"]))
    psl_path = snapshot_rows[-1][0] / config.build.public_suffix_list_filename
    psl = PublicSuffixList.from_file(psl_path)
    samples, exclusions, diagnostics = _make_samples(snapshot_rows, psl, config)
    if not samples or {sample.label for sample in samples} != {"legitimate", "phishing"}:
        raise DatasetBuildError("Processed dataset must contain both labels")

    destination = (output_dir or (config.processed_dir / config.dataset_version)).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    output_files = _write_samples(samples, destination)

    conventional = conventional_split(samples, config.build.split_ratios, config.seed)
    host_unseen = host_unseen_split(samples, config.build.split_ratios, config.seed)
    temporal, temporal_reason = temporal_split(
        samples,
        config.build.split_ratios,
        config.build.minimum_temporal_span_days,
    )
    temporal_filtered, temporal_excluded = temporal_host_unseen(samples, temporal) if temporal else ({}, 0)
    split_values = {
        "conventional": conventional,
        "host_unseen": host_unseen,
        "temporal": temporal,
        "temporal_host_unseen": temporal_filtered,
    }
    for name, assignments in split_values.items():
        output_files.append(_write_assignments(name, assignments, destination))

    psl_hashes = sorted(
        {
            sha256_file(snapshot_dir / config.build.public_suffix_list_filename)
            for snapshot_dir, _ in snapshot_rows
        }
    )
    temporal_filtered_has_test = "test" in temporal_filtered.values()
    statistics = {
        "schema_version": 1,
        "dataset_version": config.dataset_version,
        "samples": len(samples),
        "labels": dict(sorted(Counter(sample.label for sample in samples).items())),
        "sources": dict(sorted(Counter(sample.source for sample in samples).items())),
        "unique_hosts": len({sample.host for sample in samples}),
        "unique_registered_domains": len({sample.registered_domain for sample in samples}),
        "snapshot_count": len(snapshot_rows),
        "observed_at_min": min(sample.observed_at for sample in samples),
        "observed_at_max": max(sample.observed_at for sample in samples),
        "exclusions": exclusions,
        "diagnostics": diagnostics,
        "public_suffix_list": {
            "selected_sha256": sha256_file(psl_path),
            "distinct_snapshot_hashes": psl_hashes,
            "policy": "latest_snapshot_applied_to_all_samples",
        },
        "splits": {},
        "temporal_host_unseen_excluded_test_samples": temporal_excluded,
    }
    for name, assignments in split_values.items():
        unavailable = name.startswith("temporal") and not temporal
        filtered_empty = name == "temporal_host_unseen" and temporal and not temporal_filtered_has_test
        statistics["splits"][name] = {
            "status": "unavailable" if unavailable or filtered_empty else "ready",
            "reason": (
                temporal_reason
                if unavailable
                else "no_unseen_domains_in_temporal_test"
                if filtered_empty
                else None
            ),
            **_split_summary(samples, assignments),
        }
    statistics_path = destination / "statistics.json"
    statistics_path.write_text(
        json.dumps(statistics, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    output_files.append(statistics_path)

    root = config.source_path.parent.parent
    manifest = {
        "schema_version": 1,
        "dataset_version": config.dataset_version,
        "generated_at": max(manifest["observed_at"] for _, manifest in snapshot_rows),
        "pipeline_version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": _git_commit(root),
        "code_files": _code_files(root),
        "seed": config.seed,
        "config_sha256": sha256_text(canonical_json(config.raw)),
        "snapshots": [
            {"snapshot_id": manifest["snapshot_id"], "observed_at": manifest["observed_at"]}
            for _, manifest in snapshot_rows
        ],
        "inputs": sorted(input_files, key=lambda item: (item["snapshot_id"], item["name"])),
        "outputs": [
            {
                "path": path.relative_to(destination).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(output_files, key=lambda path: path.as_posix())
        ],
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination
