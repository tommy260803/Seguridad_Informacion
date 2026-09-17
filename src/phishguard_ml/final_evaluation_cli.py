from __future__ import annotations
import argparse
import json
from pathlib import Path
from phishguard_ml.final_evaluation import evaluate_runs

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="phisheval")
    parser.add_argument("--m0", required=True, type=Path); parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--m1", type=Path); parser.add_argument("--m2", type=Path); parser.add_argument("--m3", type=Path)
    args = parser.parse_args(argv)
    runs = {name: path for name, path in (("M0", args.m0), ("M1", args.m1), ("M2", args.m2), ("M3", args.m3)) if path is not None}
    print(json.dumps({"status": "success", **evaluate_runs(runs, args.output)}))

if __name__ == "__main__":
    main()
