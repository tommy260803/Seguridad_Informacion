from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard_ml.config import BaselineConfigError, load_baseline_config
from phishguard_ml.m2_training import M2TrainingError, train_m2


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="phishm2")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--split", required=True)
    parser.add_argument("--infra-results", required=True, type=Path)
    parser.add_argument("--content-results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        output = train_m2(load_baseline_config(args.config), args.dataset, args.split,
                          args.infra_results, args.content_results, args.output)
    except (BaselineConfigError, M2TrainingError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps({"status": "success", "output": str(output)}))


if __name__ == "__main__":
    main()
