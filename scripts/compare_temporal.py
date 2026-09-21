import json

print("=" * 80)
print("TEMPORAL SPLIT EVALUATION")
print("=" * 80)

models = {
    "M0 (host_unseen)": "artifacts/url-baseline-0.2.0",
    "M0 (temporal)": "artifacts/m0-temporal",
}

for name, path in models.items():
    m = json.loads(open(path + "/metrics.json").read())
    manifest = json.loads(open(path + "/manifest.json").read())
    t = m["partitions"]["test"]["selected_threshold"]
    print(f"\n--- {name} ---")
    print(f"  Split: {manifest.get('split', 'unknown')}")
    print(f"  Threshold: {t['threshold']:.4f}")
    print(f"  F1:        {t['f1']:.4f}")
    print(f"  Precision: {t['precision']:.4f}")
    print(f"  Recall:    {t['recall']:.4f}")
    print(f"  FPR:       {t['false_positive_rate']:.4f}")
    print(f"  PR-AUC:    {t['pr_auc']:.4f}")
    print(f"  ROC-AUC:   {t['roc_auc']:.4f}")
    print(f"  Brier:     {t['brier_score']:.4f}")
    print(f"  ECE:       {t['expected_calibration_error']:.4f}")
    cm = t["confusion_matrix"]
    print(f"  CM: TP={cm['tp']} FP={cm['fp']} FN={cm['fn']} TN={cm['tn']}")
    print(f"  Accuracy:  {t['accuracy']:.4f}")

# Delta comparison
hun = json.loads(open("artifacts/url-baseline-0.2.0/metrics.json").read())["partitions"]["test"]["selected_threshold"]
tmp = json.loads(open("artifacts/m0-temporal/metrics.json").read())["partitions"]["test"]["selected_threshold"]

print("\n" + "=" * 80)
print("DELTA: temporal - host_unseen (positive = temporal is better)")
print("=" * 80)
for metric in ["f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error"]:
    delta = tmp[metric] - hun[metric]
    print(f"  {metric:<30} {delta:>+.4f}")
