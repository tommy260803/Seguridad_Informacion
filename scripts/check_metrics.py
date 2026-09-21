import json
for name, path in [("M0", "artifacts/url-baseline-0.2.0"), ("M1-real", "artifacts/m1-real"), ("M2-real", "artifacts/m2-real"), ("M3-real", "artifacts/m3-real")]:
    m = json.loads(open(path + "/metrics.json").read())
    t = m["partitions"]["test"]["selected_threshold"]
    print(f"{name:10s}: F1={t['f1']:.4f} Prec={t['precision']:.4f} Rec={t['recall']:.4f} FPR={t['false_positive_rate']:.4f} PR-AUC={t['pr_auc']:.4f} ROC-AUC={t['roc_auc']:.4f} ECE={t['expected_calibration_error']:.4f}")
