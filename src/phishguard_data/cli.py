from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard_data.acquire import fetch_snapshot
from phishguard_data.config import ConfigError, load_config
from phishguard_data.pipeline import DatasetBuildError, build_dataset


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishdata",
        description="Reproducible phishing dataset acquisition and preparation",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    fetch = subparsers.add_parser("fetch", help="Download and hash a source snapshot")
    fetch.add_argument("--config", required=True, type=Path)

    build = subparsers.add_parser("build", help="Build a versioned dataset from snapshots")
    build.add_argument("--config", required=True, type=Path)
    build.add_argument("--snapshot", required=True, action="append", type=Path)
    build.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "fetch":
            path = fetch_snapshot(config)
            result = {"status": "ok", "snapshot": str(path)}
        else:
            path = build_dataset(config, args.snapshot, args.output)
            result = {"status": "ok", "dataset": str(path)}
    except (ConfigError, DatasetBuildError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps(result, ensure_ascii=False))
