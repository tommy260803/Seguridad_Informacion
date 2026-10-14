"""Train M0 on temporal and temporal_host_unseen splits with full SHA-256 verification."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.config import load_baseline_config
from phishguard_ml.training import train_url_baseline

DATASET = Path("data/processed/0.1.0")
CACHE_176K = Path("artifacts/feature-cache-176201.npz")


def main() -> None:
    config = load_baseline_config("configs/url-baseline.json")
    for split_name, out_name, cache_path in (
        ("temporal", "artifacts/m0-temporal", CACHE_176K),
        ("temporal_host_unseen", "artifacts/m0-temporal-host-unseen", None),
    ):
        out = Path(out_name)
        if out.exists():
            shutil.rmtree(out)
        path = train_url_baseline(config, DATASET, split_name, out, feature_cache=cache_path)
        print(f"M0 ({split_name}) saved to: {path}", flush=True)


if __name__ == "__main__":
    main()
