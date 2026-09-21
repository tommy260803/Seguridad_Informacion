"""Generate coverage-risk curves and abstention analysis for all models."""
import json
import csv
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, "src")

from phishguard_ml.evaluation import coverage_risk_curve, select_abstention_threshold
from phishguard_ml.training import _load_rows, _indices_for
import joblib

DATASET = Path("data/processed/0.1.0")
ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "evaluation"
OUTPUT.mkdir(parents=True, exist_ok=True)

SPLIT = "host_unseen"
rows = _load_rows(DATASET.resolve(), SPLIT)
test_idx = _indices_for(rows, lambda r: r.partition == "test")
y_test = np.asarray([r.label for r in rows], dtype=np.int8)[test_idx]

all_curves = {}
for name in ["M0", "M1", "M2", "M3"]:
    artifact_dir = ARTIFACTS / ("url-baseline-0.2.0" if name == "M0" else f"{name.lower()}-baseline")
    pred_csv = artifact_dir / "predictions.csv"
    if not pred_csv.exists():
        print(f"WARNING: {name} has no predictions.csv, skipping", flush=True)
        continue
    probs = []
    with open(pred_csv, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["partition"] == "test":
                probs.append(float(row["probability_phishing"]))
    probs = np.array(probs)
    curve = coverage_risk_curve(y_test, probs)
    abstention = select_abstention_threshold(y_test, probs, maximum_risk=0.05, minimum_coverage=0.5)
    all_curves[name] = {"curve": curve, "abstention": abstention}

model_names = list(all_curves.keys())

print("=" * 90)
print("COVERAGE-RISK CURVE (Abstention Analysis)")
print("=" * 90)
header = f"{'Conf Thresh':>12}" + "".join(f"{'Cov_'+n:>10}{'Risk_'+n:>10}" for n in model_names)
print(header)
print("-" * 90)
for i, threshold in enumerate([round(x / 20, 2) for x in range(0, 21)]):
    row = f"{threshold:>12.2f}"
    for name in model_names:
        c = all_curves[name]["curve"][i]
        row += f"{c['coverage']:>10.4f}{c['selective_risk']:>10.4f}"
    print(row)

print("\n" + "=" * 90)
print("ABSTENTION THRESHOLDS (max_risk=5%, min_coverage=50%)")
print("=" * 90)
for name in model_names:
    a = all_curves[name]["abstention"]
    print(f"  {name}: conf_thresh={a['confidence_threshold']:.2f}  coverage={a['coverage']:.4f}  abstention={a['abstention_rate']:.4f}  risk={a['selective_risk']:.4f}")

csv_path = OUTPUT / "coverage_risk_curves.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["confidence_threshold"] + [f"{n}_coverage" for n in model_names] + [f"{n}_risk" for n in model_names])
    for i, threshold in enumerate([round(x / 20, 2) for x in range(0, 21)]):
        row = [threshold]
        for name in model_names:
            row.append(all_curves[name]["curve"][i]["coverage"])
        for name in model_names:
            row.append(all_curves[name]["curve"][i]["selective_risk"])
        writer.writerow(row)

print(f"\nCSV written to: {csv_path}")
