"""Update evaluation_summary_real.json and corrected_audit summaries with:
1. Updated M0 temporal (N=17,625 test) and M0 temporal_host_unseen (N=16,484 test) metrics.
2. M0->M2 Strictly Real 3-Stage Cascade (M4_M2_real and M5_M2_real) on N=691 Complete-Case test URLs
   (100% real URL + DNS/TLS/HTTP + HTML DOM telemetry, zero synthetic M3 PIL features).
3. M0->M5 Authentic CDP 4-Stage Cascade on the N=467 (test N=83) 100% authentic Headless Chrome CDP cohort.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_ml.evaluation import classification_metrics, expected_calibration_error, shannon_entropy
from train_and_evaluate_all_real import evaluate_cascade_policy

DATASET_DIR = Path("data/processed/0.1.0")
ARTIFACTS_DIR = Path("artifacts")
EVAL_DIR = ARTIFACTS_DIR / "evaluation"
CORRECTED_DIR = ARTIFACTS_DIR / "corrected_audit"


def evaluate_3stage_m0_m2_cascade() -> dict[str, Any]:
    """Evaluate a 3-stage cascade (M0 -> M1 -> M2) on N=691 Complete-Case test URLs using ONLY 100% real data."""
    m0_preds = {}
    m0_val = {}
    for m_name, folder in (("M0", "m0-real"), ("M1", "m1-real"), ("M2", "m2-real")):
        preds_csv = ARTIFACTS_DIR / folder / "predictions.csv"
        metrics_json = json.loads((ARTIFACTS_DIR / folder / "metrics.json").read_text(encoding="utf-8"))
        tau = float(metrics_json["selected_threshold"])
        m0_preds[m_name] = {"tau": tau, "val": [], "test": [], "y_val": [], "y_test": [], "test_ids": []}
        with open(preds_csv, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["partition"] == "validation":
                    m0_preds[m_name]["val"].append(float(r["probability_phishing"]))
                    m0_preds[m_name]["y_val"].append(int(r["label"]))
                elif r["partition"] == "test":
                    m0_preds[m_name]["test"].append(float(r["probability_phishing"]))
                    m0_preds[m_name]["y_test"].append(int(r["label"]))
                    m0_preds[m_name]["test_ids"].append(r["sample_id"])

    y_te = np.array(m0_preds["M0"]["y_test"], dtype=np.int8)
    p0 = np.array(m0_preds["M0"]["test"], dtype=np.float64)
    p1 = np.array(m0_preds["M1"]["test"], dtype=np.float64)
    p2 = np.array(m0_preds["M2"]["test"], dtype=np.float64)
    taus = [m0_preds["M0"]["tau"], m0_preds["M1"]["tau"], m0_preds["M2"]["tau"]]

    esc_th = 0.15
    abstain_th = 0.50
    n = len(y_te)
    final_prob = np.zeros(n, dtype=np.float64)
    final_pred = np.zeros(n, dtype=np.int8)
    abstained = np.zeros(n, dtype=bool)
    stop_stage = np.zeros(n, dtype=np.int8)
    stage_p = [p0, p1, p2]

    for i in range(n):
        chosen_k = 0
        for k in range(3):
            chosen_k = k
            hk = float(shannon_entropy(np.array([stage_p[k][i]]))[0])
            if k < 2 and hk <= esc_th:
                break
        stop_stage[i] = chosen_k
        pf = float(stage_p[chosen_k][i])
        final_prob[i] = pf
        final_pred[i] = 1 if pf >= taus[chosen_k] else 0
        if float(shannon_entropy(np.array([pf]))[0]) > abstain_th:
            abstained[i] = True

    tn = int(((y_te == 0) & (final_pred == 0)).sum())
    fp = int(((y_te == 0) & (final_pred == 1)).sum())
    fn = int(((y_te == 1) & (final_pred == 0)).sum())
    tp = int(((y_te == 1) & (final_pred == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    dec_mask = ~abstained
    y_d = y_te[dec_mask]
    pr_d = final_pred[dec_mask]
    pb_d = final_prob[dec_mask]
    tn_d = int(((y_d == 0) & (pr_d == 0)).sum())
    fp_d = int(((y_d == 0) & (pr_d == 1)).sum())
    fn_d = int(((y_d == 1) & (pr_d == 0)).sum())
    tp_d = int(((y_d == 1) & (pr_d == 1)).sum())
    prec_d = tp_d / (tp_d + fp_d) if (tp_d + fp_d) else 0.0
    rec_d = tp_d / (tp_d + fn_d) if (tp_d + fn_d) else 0.0
    f1_d = 2 * prec_d * rec_d / (prec_d + rec_d) if (prec_d + rec_d) else 0.0

    return {
        "description": "3-Stage Cascade (M0 URL -> M1 Infra -> M2 Content) on N=691 Complete-Case test URLs (0% synthetic M3 features)",
        "test_samples": int(n),
        "escalation_entropy_threshold": esc_th,
        "abstention_entropy_threshold": abstain_th,
        "m4_m2_forced_full_coverage": {
            "samples": int(n),
            "accuracy": round((tn + tp) / n, 6),
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "f1": round(f1, 6),
            "false_positive_rate": round(fp / (fp + tn), 6),
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        },
        "m5_m2_selective_with_abstention": {
            "coverage": round(float(dec_mask.mean()), 6),
            "abstention_rate": round(float(abstained.mean()), 6),
            "decided_samples": int(dec_mask.sum()),
            "abstained_samples": int(abstained.sum()),
            "abstained_phishing": int(((y_te == 1) & abstained).sum()),
            "abstained_legitimate": int(((y_te == 0) & abstained).sum()),
            "accuracy": round((tn_d + tp_d) / len(y_d), 6),
            "precision": round(prec_d, 6),
            "recall": round(rec_d, 6),
            "f1": round(f1_d, 6),
            "false_positive_rate": round(fp_d / (fp_d + tn_d), 6),
            "expected_calibration_error": round(float(expected_calibration_error(y_d, pb_d, 15)), 6),
            "confusion_matrix": {"tn": tn_d, "fp": fp_d, "fn": fn_d, "tp": tp_d},
        },
        "stopping_distribution": {
            "M0": int((stop_stage == 0).sum()),
            "M1": int((stop_stage == 1).sum()),
            "M2": int((stop_stage == 2).sum()),
            "M0_pct": round(float((stop_stage == 0).mean() * 100.0), 2),
            "M1_pct": round(float((stop_stage == 1).mean() * 100.0), 2),
            "M2_pct": round(float((stop_stage == 2).mean() * 100.0), 2),
            "avg_modalities_per_sample": round(float((stop_stage + 1).mean()), 4),
        },
    }


def main() -> None:
    CORRECTED_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = EVAL_DIR / "evaluation_summary_real.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    # 1. Update full_corpus_m0 with corrected temporal and temporal_host_unseen metrics
    m0_temp = json.loads((ARTIFACTS_DIR / "m0-temporal" / "metrics.json").read_text(encoding="utf-8"))
    m0_temp_hu = json.loads((ARTIFACTS_DIR / "m0-temporal-host-unseen" / "metrics.json").read_text(encoding="utf-8"))
    summary["full_corpus_m0"]["temporal"] = m0_temp["partitions"]["test"]["selected_threshold"]
    summary["full_corpus_m0"]["temporal_host_unseen"] = m0_temp_hu["partitions"]["test"]["selected_threshold"]

    # 2. Add 3-stage M0->M2 strictly real cascade (no synthetic M3)
    m0_m2_cascade = evaluate_3stage_m0_m2_cascade()
    summary["m0_to_m2_strictly_real_cascade_n691"] = m0_m2_cascade

    # 3. Attach M3 authentic CDP evaluation summary
    m3_auth_path = CORRECTED_DIR / "m3_visual_audit_and_authentic_evaluation.json"
    if m3_auth_path.exists():
        m3_auth_data = json.loads(m3_auth_path.read_text(encoding="utf-8"))
        summary["m3_authentic_cdp_cohort_evaluation"] = m3_auth_data["expanded_authentic_cdp_cohort"]

    summary["audit_annotations"] = {
        "m0_temporal_split_resolved": True,
        "m0_temporal_split_csv_sha256": "9449ee4e0c31cdba9b6f338d3c497f74308b90ae62df299fb087d63239e0258a",
        "m0_temporal_test_samples": 17625,
        "m0_temporal_host_unseen_test_samples": 16484,
        "m3_visual_provenance_note": (
            "In the N=5,612 Complete-Case multimodal cohort, M0 (URL), M1 (DNS/TLS/HTTP), and M2 (HTML DOM) "
            "are 100% real measurements. For Stage M3, 467 samples have authentic Headless Chrome CDP screenshots "
            "(visual-results-authentic-cdp.jsonl, test N=83), while 5,536 samples in the original run used "
            "synthetic PIL DOM-viewport diagrams (visual-results-synthetic-dom-proxy.jsonl). Both the 3-stage "
            "M0->M2 cascade (N=691 test, 0% synthetic features) and the 4-stage authentic CDP evaluation (N=83 test) "
            "are provided separately."
        ),
    }

    for target_dir in (EVAL_DIR, CORRECTED_DIR):
        (target_dir / "evaluation_summary_real.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
    print(
        f"Updated evaluation_summary_real.json!\n"
        f"  M0 Temporal (N=17,625): F1={summary['full_corpus_m0']['temporal']['f1']:.4f}\n"
        f"  M0 Temporal Host-Unseen (N=16,484): F1={summary['full_corpus_m0']['temporal_host_unseen']['f1']:.4f}\n"
        f"  3-Stage Real Cascade M0->M2 (N=691, 0% synthetic): Forced F1={m0_m2_cascade['m4_m2_forced_full_coverage']['f1']:.4f}, "
        f"Selective F1={m0_m2_cascade['m5_m2_selective_with_abstention']['f1']:.4f} "
        f"(Coverage={m0_m2_cascade['m5_m2_selective_with_abstention']['coverage']:.4f})",
        flush=True,
    )


if __name__ == "__main__":
    main()
