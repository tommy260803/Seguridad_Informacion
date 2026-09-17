from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard_ml.config import BaselineConfigError, load_baseline_config
from phishguard_ml.training import BaselineTrainingError, train_url_baseline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishbaseline", description="Train and evaluate URL-only baseline")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--split", required=True, choices=("conventional", "host_unseen", "temporal"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--feature-cache", type=Path)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        config = load_baseline_config(args.config)
        result = train_url_baseline(
            config,
            args.dataset,
            args.split,
            args.output,
            args.feature_cache,
        )
    except (BaselineConfigError, BaselineTrainingError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps({"status": "ok", "experiment": str(result)}, ensure_ascii=False))
