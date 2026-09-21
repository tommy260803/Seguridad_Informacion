"""Comprehensive evaluation of all models with real analysis results."""
import json
import csv
import numpy as np
from pathlib import Path

ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "evaluation"
OUTPUT.mkdir(parents=True, exist_ok=True)

METRICS = ("f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error")

models = {
    "M0": ARTIFACTS / "url-baseline-0.2.0",
    "M1": ARTIFACTS / "m1-real",
    "M2": ARTIFACTS / "m2-real",
    "M3": ARTIFACTS / "m3-real",
}

feature_counts = {"M0": 11, "M1": 29, "M2": 50, "M3": 59}

results = {}
for name, path in models.items():
    metrics = json.loads((path / "metrics.json").read_text(encoding="utf-8"))
    results[name] = metrics

# Table 1: Test set comparison
print("=" * 100)
print("TABLE 1: Test Set Performance (host_unseen, real analysis results)")
print("=" * 100)
header = f"{'Model':<8} {'Feat':>5} {'F1':>8} {'Prec':>8} {'Recall':>8} {'FPR':>8} {'PR-AUC':>8} {'ROC-AUC':>8} {'Brier':>8} {'ECE':>8}"
print(header)
print("-" * 100)
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["partitions"]["test"]["selected_threshold"]
    print(f"{name:<8} {feature_counts[name]:>5} {t['f1']:.4f}   {t['precision']:.4f}   {t['recall']:.4f}   {t['false_positive_rate']:.4f}   {t['pr_auc']:.4f}   {t['roc_auc']:.4f}   {t['brier_score']:.4f}   {t['expected_calibration_error']:.4f}")

# Table 2: Delta vs M0
print("\n" + "=" * 100)
print("TABLE 2: Delta vs M0 (positive = improvement)")
print("=" * 100)
header = f"{'Metric':<30} {'M1-M0':>12} {'M2-M0':>12} {'M3-M0':>12}"
print(header)
print("-" * 66)
m0_test = results["M0"]["partitions"]["test"]["selected_threshold"]
for metric in METRICS:
    vals = []
    for name in ["M1", "M2", "M3"]:
        t = results[name]["partitions"]["test"]["selected_threshold"]
        vals.append(t[metric] - m0_test[metric])
    print(f"{metric:<30} {vals[0]:>+12.6f} {vals[1]:>+12.6f} {vals[2]:>+12.6f}")

# Table 3: Confusion matrices
print("\n" + "=" * 100)
print("TABLE 3: Confusion Matrices (test, selected threshold)")
print("=" * 100)
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["partitions"]["test"]["selected_threshold"]
    cm = t["confusion_matrix"]
    print(f"\n  {name}: TP={cm['tp']:>5} FP={cm['fp']:>5} FN={cm['fn']:>5} TN={cm['tn']:>5}  (Acc={t['accuracy']:.4f})")

# Table 4: Per-partition
print("\n" + "=" * 100)
print("TABLE 4: Per-Partition F1 and ECE")
print("=" * 100)
header = f"{'Model':<8}" + "".join(f" {p:>20}" for p in ["train", "validation", "test"])
print(header)
print("-" * 100)
for metric in ["f1", "expected_calibration_error"]:
    print(f"\n  {metric}:")
    for name in ["M0", "M1", "M2", "M3"]:
        vals = []
        for partition in ["train", "validation", "test"]:
            t = results[name]["partitions"][partition]["selected_threshold"]
            vals.append(f"{t[metric]:.4f}")
        print(f"    {name:<8} {'  '.join(f'{v:>10}' for v in vals)}")

# Write summary JSON
summary = {
    "schema_version": 1,
    "split": "host_unseen",
    "dataset_version": "0.1.0",
    "analysis_type": "real_infrastructure_and_content",
    "analyzed_urls": 2000,
    "infra_success_rate": 0.783,
    "content_success_rate": 0.566,
    "models": {}
}
for name in ["M0", "M1", "M2", "M3"]:
    t = results[name]["partitions"]["test"]["selected_threshold"]
    summary["models"][name] = {
        "feature_count": feature_counts[name],
        "test_metrics": {m: round(t[m], 6) for m in METRICS},
        "confusion_matrix": t["confusion_matrix"],
        "accuracy": round(t["accuracy"], 6),
    }

json_path = OUTPUT / "evaluation_summary_real.json"
json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"\nJSON written to: {json_path}")

# Write CSV
csv_path = OUTPUT / "evaluation_report_real.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["model", "features", "partition"] + list(METRICS) + ["accuracy", "tn", "fp", "fn", "tp"])
    for name in ["M0", "M1", "M2", "M3"]:
        for partition in ["train", "validation", "test"]:
            p = results[name]["partitions"][partition]["selected_threshold"]
            cm = p["confusion_matrix"]
            writer.writerow([name, feature_counts[name], partition] + [p.get(m, 0.0) for m in METRICS] + [p["accuracy"], cm["tn"], cm["fp"], cm["fn"], cm["tp"]])
print(f"CSV written to: {csv_path}")
