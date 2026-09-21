"""Train M0 on temporal split and compare with host_unseen."""
import sys
import shutil
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.config import load_baseline_config
from phishguard_ml.training import train_url_baseline

DATASET = Path("data/processed/0.1.0")
SPLIT = "temporal"
OUT = Path("artifacts/m0-temporal")

if OUT.exists():
    shutil.rmtree(OUT)

config = load_baseline_config("configs/url-baseline.json")
path = train_url_baseline(config, DATASET, SPLIT, OUT)
print(f"M0 temporal saved to: {path}")
