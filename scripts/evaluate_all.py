"""Comprehensive evaluation of all trained models (M0-M3)."""
import json
import csv
import numpy as np
from pathlib import Path

ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "evaluation"
OUTPUT.mkdir(parents=True, exist_ok=True)

METRICS = ("f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error")

# Load all model metrics
models = {
    "M0": ARTIFACTS / "url-baseline-0.2.0",
    "M1": ARTIFACTS / "m1-baseline",
    "M2": ARTIFACTS / "m2-baseline",
    "M3": ARTIFACTS / "m3-baseline",
}

results = {}
for name, path in models.items():
    metrics = json.loads((path / "metrics.json").read_text(encoding="utf-8"))
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    results[name] = {"metrics": metrics, "manifest": manifest}

# --- Table 1: Test set comparison ---
print("=" * 80)
print("TABLE 1: Test Set Performance Comparison (host_unseen split)")
print("=" * 80)
header = f"{'Model':<6} {'Features':<8} {'F1':>8} {'Prec':>8} {'Recall':>8} {'FPR':>8} {'PR-AUC':>8} {'ROC-AUC':>8} {'Brier':>8} {'ECE':>8}"
print(header)
print("-" * 80)

feature_counts = {"M0": 11, "M1": 29, "M2": 50, "M3": 59}
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["metrics"]["partitions"]["test"]["selected_threshold"]
    print(f"{name:<6} {feature_counts[name]:<8} {t['f1']:.4f}   {t['precision']:.4f}   {t['recall']:.4f}   {t['false_positive_rate']:.4f}   {t['pr_auc']:.4f}   {t['roc_auc']:.4f}   {t['brier_score']:.4f}   {t['expected_calibration_error']:.4f}")

# --- Table 2: Per-partition details ---
print("\n" + "=" * 80)
print("TABLE 2: Per-Partition Metrics (selected threshold)")
print("=" * 80)
for name in ["M0", "M1", "M2", "M3"]:
    print(f"\n--- {name} ---")
    for partition in ["train", "validation", "test"]:
        p = results[name]["metrics"]["partitions"][partition]["selected_threshold"]
        cm = p["confusion_matrix"]
        print(f"  {partition:<12} n={p['samples']:>6}  TP={cm['tp']:>5} FP={cm['fp']:>5} FN={cm['fn']:>5} TN={cm['tn']:>5}  Acc={p['accuracy']:.4f}  F1={p['f1']:.4f}")

# --- Table 3: Delta M1-M0, M2-M0, M3-M0 ---
print("\n" + "=" * 80)
print("TABLE 3: Delta vs M0 (test set, positive = improvement)")
print("=" * 80)
header = f"{'Metric':<30} {'M1-M0':>10} {'M2-M0':>10} {'M3-M0':>10}"
print(header)
print("-" * 60)
m0_test = results["M0"]["metrics"]["partitions"]["test"]["selected_threshold"]
for metric in METRICS:
    vals = []
    for name in ["M1", "M2", "M3"]:
        t = results[name]["metrics"]["partitions"]["test"]["selected_threshold"]
        vals.append(t[metric] - m0_test[metric])
    print(f"{metric:<30} {vals[0]:>+10.4f} {vals[1]:>+10.4f} {vals[2]:>+10.4f}")

# --- Confusion Matrix Summary ---
print("\n" + "=" * 80)
print("TABLE 4: Confusion Matrices at Test Set (selected threshold)")
print("=" * 80)
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["metrics"]["partitions"]["test"]["selected_threshold"]
    cm = t["confusion_matrix"]
    print(f"\n{name}:")
    print(f"  Predicted:    Neg      Pos")
    print(f"  Actual Neg:  {cm['tn']:>5}    {cm['fp']:>5}")
    print(f"  Actual Pos:  {cm['fn']:>5}    {cm['tp']:>5}")

# --- Write CSV ---
csv_path = OUTPUT / "evaluation_report.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["model", "features", "partition"] + list(METRICS) + ["accuracy", "tn", "fp", "fn", "tp"])
    for name in ["M0", "M1", "M2", "M3"]:
        for partition in ["train", "validation", "test"]:
            p = results[name]["metrics"]["partitions"][partition]["selected_threshold"]
            cm = p["confusion_matrix"]
            writer.writerow([
                name, feature_counts[name], partition,
                *[p.get(m, 0.0) for m in METRICS],
                p["accuracy"], cm["tn"], cm["fp"], cm["fn"], cm["tp"]
            ])
print(f"\nCSV written to: {csv_path}")

# --- Write JSON summary ---
summary = {
    "schema_version": 1,
    "split": "host_unseen",
    "dataset_version": "0.1.0",
    "dataset_samples": results["M0"]["metrics"]["partitions"]["test"]["selected_threshold"]["samples"] +
                       results["M0"]["metrics"]["partitions"]["validation"]["selected_threshold"]["samples"] +
                       results["M0"]["metrics"]["partitions"]["train"]["selected_threshold"]["samples"],
    "models": {}
}
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["metrics"]["partitions"]["test"]["selected_threshold"]
    summary["models"][name] = {
        "feature_count": feature_counts[name],
        "test_metrics": {m: round(t[m], 6) for m in METRICS},
        "confusion_matrix": t["confusion_matrix"],
        "accuracy": round(t["accuracy"], 6),
        "selected_candidate": results[name]["metrics"].get("selected_candidate", "unknown"),
    }

json_path = OUTPUT / "evaluation_summary.json"
json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"JSON written to: {json_path}")

print("\n" + "=" * 80)
print("EVALUATION COMPLETE")
print("=" * 80)
