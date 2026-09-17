from __future__ import annotations
import argparse
from pathlib import Path
from phishguard_ml.config import load_baseline_config
from phishguard_ml.m3_training import train_m3

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="phishm3")
    for name in ("config", "dataset", "infra-results", "content-results", "visual-results", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--split", required=True)
    args = parser.parse_args(argv)
    output = train_m3(load_baseline_config(args.config), args.dataset, args.split, args.infra_results, args.content_results, args.visual_results, args.output)
    print(f'{{"status":"success","output":"{output}"}}')

if __name__ == "__main__":
    main()
