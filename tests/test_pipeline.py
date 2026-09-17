import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from phishguard_data.config import load_config
from phishguard_data.hashing import sha256_file
from phishguard_data.pipeline import build_dataset


def write_config(root: Path) -> Path:
    config_dir = root / "configs"
    config_dir.mkdir()
    config = {
        "schema_version": 1,
        "dataset_version": "fixture-v1",
        "seed": 42,
        "paths": {"raw_dir": "data/raw", "processed_dir": "data/processed"},
        "acquisition": {
            "user_agent": "pipeline-test/1.0",
            "timeout_seconds": 5,
            "max_download_bytes": 1000000,
            "sources": [
                {
                    "name": "phishtank",
                    "url": "https://example.test/phish.csv",
                    "filename": "phish.csv",
                },
                {
                    "name": "tranco",
                    "url": "https://example.test/tranco.csv",
                    "filename": "tranco.csv",
                },
                {
                    "name": "public_suffix_list",
                    "url": "https://example.test/psl.dat",
                    "filename": "psl.dat",
                },
            ],
        },
        "build": {
            "phishtank_filename": "phish.csv",
            "tranco_filename": "tranco.csv",
            "public_suffix_list_filename": "psl.dat",
            "tranco_limit": 100,
            "allowed_schemes": ["http", "https"],
            "max_url_length": 2048,
            "minimum_temporal_span_days": 2,
            "split_ratios": {"train": 0.7, "validation": 0.15, "test": 0.15},
        },
    }
    path = config_dir / "test.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def write_snapshot(root: Path, day: int) -> Path:
    observed = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)
    observed_at = observed.isoformat().replace("+00:00", "Z")
    snapshot = root / "snapshots" / f"snapshot-{day}"
    snapshot.mkdir(parents=True)
    phish = snapshot / "phish.csv"
    tranco = snapshot / "tranco.csv"
    psl = snapshot / "psl.dat"
    phish.write_text(
        "phish_id,url,submission_time,verified,verification_time,online,target\n"
        + "".join(
            f"{day * 10 + item},https://login-{day}-{item}.bad.com/auth,2025-01-01T00:00:00Z,yes,2025-01-02T00:00:00Z,yes,Bank\n"
            for item in range(4)
        )
        + "999,https://repeat.bad.com/,2025-01-01T00:00:00Z,yes,2025-01-02T00:00:00Z,yes,Bank\n",
        encoding="utf-8",
    )
    tranco.write_text(
        "".join(f"{item + 1},good-{day}-{item}.com\n" for item in range(4))
        + "10,repeat-good.com\n",
        encoding="utf-8",
    )
    psl.write_text("com\norg\n", encoding="utf-8")
    source_files = [
        ("phishtank", phish),
        ("tranco", tranco),
        ("public_suffix_list", psl),
    ]
    manifest = {
        "schema_version": 1,
        "snapshot_id": snapshot.name,
        "observed_at": observed_at,
        "sources": [
            {
                "name": name,
                "filename": path.name,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for name, path in source_files
        ],
    }
    (snapshot / "acquisition-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return snapshot


def test_build_dataset_is_reproducible_and_audited(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path))
    snapshots = [write_snapshot(tmp_path, day) for day in range(4)]

    first = build_dataset(config, snapshots, tmp_path / "result-a")
    second = build_dataset(config, snapshots, tmp_path / "result-b")

    first_manifest = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((second / "manifest.json").read_text(encoding="utf-8"))
    assert first_manifest["outputs"] == second_manifest["outputs"]

    statistics = json.loads((first / "statistics.json").read_text(encoding="utf-8"))
    assert statistics["samples"] == 34
    assert statistics["labels"] == {"legitimate": 17, "phishing": 17}
    assert statistics["exclusions"]["duplicate_same_label"] == 6
    assert statistics["splits"]["temporal"]["status"] == "ready"
    host_leakage = statistics["splits"]["host_unseen"]["leakage_audit"]
    assert host_leakage["domains_train_test"] == 0
    assert host_leakage["domains_validation_test"] == 0


def test_single_snapshot_marks_temporal_split_unavailable(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path))
    snapshot = write_snapshot(tmp_path, 0)

    result = build_dataset(config, [snapshot], tmp_path / "result")
    statistics = json.loads((result / "statistics.json").read_text(encoding="utf-8"))

    assert statistics["splits"]["temporal"]["status"] == "unavailable"
    assert statistics["splits"]["temporal"]["reason"] == "requires_at_least_three_snapshot_timestamps"
