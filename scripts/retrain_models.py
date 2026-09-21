"""Retrain M1, M2, M3 with real analysis results."""
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.config import load_baseline_config
from phishguard_ml.m1_training import train_m1
from phishguard_ml.m2_training import train_m2
from phishguard_ml.m3_training import train_m3

DATASET = Path("data/processed/0.1.0")
SPLIT = "host_unseen"
INFRA_RESULTS = Path("artifacts/analysis-results/infrastructure-results-real.jsonl")
CONTENT_RESULTS = Path("artifacts/analysis-results/content-results-real.jsonl")

# Output directories (new names to avoid overwriting synthetic results)
M1_OUT = Path("artifacts/m1-real")
M2_OUT = Path("artifacts/m2-real")
M3_OUT = Path("artifacts/m3-real")


def clean_and_train(out_dir: Path):
    if out_dir.exists():
        shutil.rmtree(out_dir)
        print(f"  Removed old {out_dir}")


# === M1 ===
print("=" * 60)
print("Training M1 (URL + Infrastructure)")
print("=" * 60)
config_m1 = load_baseline_config("configs/m1.json")
clean_and_train(M1_OUT)
m1_path = train_m1(config_m1, DATASET, SPLIT, INFRA_RESULTS, M1_OUT)
print(f"M1 saved to: {m1_path}")

# === M2 ===
print("\n" + "=" * 60)
print("Training M2 (URL + Infrastructure + Content)")
print("=" * 60)
config_m2 = load_baseline_config("configs/m2.json")
clean_and_train(M2_OUT)
m2_path = train_m2(config_m2, DATASET, SPLIT, INFRA_RESULTS, CONTENT_RESULTS, M2_OUT)
print(f"M2 saved to: {m2_path}")

# === M3 ===
print("\n" + "=" * 60)
print("Training M3 (URL + Infrastructure + Content + Visual)")
print("=" * 60)
config_m3 = load_baseline_config("configs/m3.json")
clean_and_train(M3_OUT)
# M3 requires visual results - use empty path since we don't have visual analysis
# The visual_feature_matrix function handles None/missing by returning zeros
m3_path = train_m3(config_m3, DATASET, SPLIT, INFRA_RESULTS, CONTENT_RESULTS, Path("artifacts/analysis-results/visual-results-real.jsonl"), M3_OUT)
print(f"M3 saved to: {m3_path}")

print("\n" + "=" * 60)
print("ALL MODELS RETRAINED SUCCESSFULLY")
print("=" * 60)
print(f"  M1: {m1_path}")
print(f"  M2: {m2_path}")
print(f"  M3: {m3_path}")
