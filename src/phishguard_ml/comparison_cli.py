from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishguard_ml.comparison import ComparisonError, compare_m0_m1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="phishcompare")
    parser.add_argument("--m0", required=True, type=Path)
    parser.add_argument("--m1", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = compare_m0_m1(args.m0, args.m1, args.output)
    except (ComparisonError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps({"status": "success", "output": str(args.output), "split": result["split"]}))


if __name__ == "__main__":
    main()
