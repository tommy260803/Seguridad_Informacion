"""Train M3 only."""
import sys
import shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.config import load_baseline_config
from phishguard_ml.m3_training import train_m3

DATASET = Path("data/processed/0.1.0")
SPLIT = "host_unseen"
INFRA = Path("artifacts/analysis-results/infrastructure-results-real.jsonl")
CONTENT = Path("artifacts/analysis-results/content-results-real.jsonl")
VISUAL = Path("artifacts/analysis-results/visual-results-real.jsonl")
OUT = Path("artifacts/m3-real")

if OUT.exists():
    shutil.rmtree(OUT)

config = load_baseline_config("configs/m3.json")
path = train_m3(config, DATASET, SPLIT, INFRA, CONTENT, VISUAL, OUT)
print(f"M3 saved to: {path}")
