from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when a pipeline configuration is invalid."""


@dataclass(frozen=True)
class SourceConfig:
    name: str
    url: str
    filename: str
    terms_url: str | None
    version_hint: str | None
    version_url: str | None


@dataclass(frozen=True)
class AcquisitionConfig:
    user_agent: str
    timeout_seconds: int
    max_download_bytes: int
    sources: tuple[SourceConfig, ...]


@dataclass(frozen=True)
class BuildConfig:
    phishtank_filename: str
    tranco_filename: str
    public_suffix_list_filename: str
    tranco_limit: int
    allowed_schemes: tuple[str, ...]
    max_url_length: int
    minimum_temporal_span_days: int
    split_ratios: dict[str, float]


@dataclass(frozen=True)
class PipelineConfig:
    schema_version: int
    dataset_version: str
    seed: int
    raw_dir: Path
    processed_dir: Path
    acquisition: AcquisitionConfig
    build: BuildConfig
    source_path: Path
    raw: dict[str, Any]


def _require(mapping: dict[str, Any], key: str, expected: type) -> Any:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise ConfigError(f"{key!r} must be {expected.__name__}")
    return value


def load_config(path: str | Path) -> PipelineConfig:
    source_path = Path(path).resolve()
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration {source_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("Configuration root must be an object")
    if raw.get("schema_version") != 1:
        raise ConfigError("Only schema_version 1 is supported")

    paths = _require(raw, "paths", dict)
    acquisition_raw = _require(raw, "acquisition", dict)
    build_raw = _require(raw, "build", dict)
    source_rows = _require(acquisition_raw, "sources", list)
    sources = tuple(
        SourceConfig(
            name=str(row["name"]),
            url=str(row["url"]),
            filename=str(row["filename"]),
            terms_url=str(row["terms_url"]) if row.get("terms_url") else None,
            version_hint=str(row["version_hint"]) if row.get("version_hint") else None,
            version_url=str(row["version_url"]) if row.get("version_url") else None,
        )
        for row in source_rows
    )
    required_sources = {"phishtank", "tranco", "public_suffix_list"}
    names = {source.name for source in sources}
    if names != required_sources:
        raise ConfigError(f"acquisition.sources must contain exactly {sorted(required_sources)}")

    ratios_raw = _require(build_raw, "split_ratios", dict)
    ratio_names = {"train", "validation", "test"}
    if set(ratios_raw) != ratio_names:
        raise ConfigError(f"split_ratios must contain exactly {sorted(ratio_names)}")
    ratios = {name: float(value) for name, value in ratios_raw.items()}
    if any(value <= 0 for value in ratios.values()) or abs(sum(ratios.values()) - 1.0) > 1e-9:
        raise ConfigError("split_ratios must be positive and sum to 1")

    base = source_path.parent.parent
    raw_dir = (base / str(paths["raw_dir"])).resolve()
    processed_dir = (base / str(paths["processed_dir"])).resolve()
    acquisition = AcquisitionConfig(
        user_agent=str(acquisition_raw["user_agent"]),
        timeout_seconds=int(acquisition_raw["timeout_seconds"]),
        max_download_bytes=int(acquisition_raw["max_download_bytes"]),
        sources=sources,
    )
    if acquisition.timeout_seconds <= 0 or acquisition.max_download_bytes <= 0:
        raise ConfigError("Acquisition limits must be positive")
    if not acquisition.user_agent.strip():
        raise ConfigError("A descriptive acquisition user_agent is required")

    build = BuildConfig(
        phishtank_filename=str(build_raw["phishtank_filename"]),
        tranco_filename=str(build_raw["tranco_filename"]),
        public_suffix_list_filename=str(build_raw["public_suffix_list_filename"]),
        tranco_limit=int(build_raw["tranco_limit"]),
        allowed_schemes=tuple(str(item).lower() for item in build_raw["allowed_schemes"]),
        max_url_length=int(build_raw["max_url_length"]),
        minimum_temporal_span_days=int(build_raw.get("minimum_temporal_span_days", 0)),
        split_ratios=ratios,
    )
    if build.tranco_limit <= 0 or build.max_url_length <= 0 or build.minimum_temporal_span_days < 0:
        raise ConfigError("Build limits must be positive")
    if not build.allowed_schemes or any(scheme not in {"http", "https"} for scheme in build.allowed_schemes):
        raise ConfigError("allowed_schemes may contain only http and https")

    return PipelineConfig(
        schema_version=1,
        dataset_version=str(raw["dataset_version"]),
        seed=int(raw["seed"]),
        raw_dir=raw_dir,
        processed_dir=processed_dir,
        acquisition=acquisition,
        build=build,
        source_path=source_path,
        raw=raw,
    )
