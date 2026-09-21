"""Retrain M1 and M2 with 10K real analysis results."""
import sys
import shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.config import load_baseline_config
from phishguard_ml.m1_training import train_m1
from phishguard_ml.m2_training import train_m2

DATASET = Path("data/processed/0.1.0")
SPLIT = "host_unseen"
INFRA = Path("artifacts/analysis-results/infrastructure-results-real.jsonl")
CONTENT = Path("artifacts/analysis-results/content-results-real.jsonl")

for name, train_fn, out_dir, args in [
    ("M1", train_m1, Path("artifacts/m1-real"), (DATASET, SPLIT, INFRA)),
    ("M2", train_m2, Path("artifacts/m2-real"), (DATASET, SPLIT, INFRA, CONTENT)),
]:
    print(f"\n{'='*60}\nTraining {name}\n{'='*60}")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    config = load_baseline_config(f"configs/{name.lower()}.json")
    path = train_fn(config, *args, out_dir)
    print(f"{name} saved to: {path}")

print("\nDONE: M1 and M2 retrained")
