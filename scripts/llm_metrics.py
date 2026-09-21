"""Compute LLM vs M0 metrics from evaluation results."""
import json
import sys
import numpy as np
from pathlib import Path
from sklearn.metrics import (
    f1_score, precision_score, recall_score, roc_auc_score,
    average_precision_score, brier_score_loss, confusion_matrix,
)
sys.stdout.reconfigure(encoding="utf-8")

OUTPUT = Path("artifacts/evaluation")
results = json.loads((OUTPUT / "llm_evaluation_results.json").read_text(encoding="utf-8"))

# All results (LLM uses M0 fallback when LLM fails)
y_true_all = np.array([r["label"] for r in results])
m0_probs = np.array([r["m0_prob"] for r in results])
llm_probs = np.array([r["llm_prob"] if r["llm_prob"] is not None else r["m0_prob"] for r in results])

# LLM-only (successful LLM predictions)
successful = [r for r in results if r["llm_prob"] is not None]
y_true_llm = np.array([r["label"] for r in successful])
llm_only_probs = np.array([r["llm_prob"] for r in successful])
m0_for_llm = np.array([r["m0_prob"] for r in successful])

print("=" * 80)
print("LLM AGENT EVALUATION RESULTS")
print("=" * 80)
print(f"\nBenchmark: {len(results)} URLs")
print(f"HTML downloaded: {sum(1 for r in results if r['llm_prob'] is not None or r['llm_error'] != 'html_download_failed')}")
print(f"LLM successful: {len(successful)}/{len(results)}")
print(f"LLM failures: {len(results) - len(successful)}")

def compute_metrics(y_true, y_prob, threshold=0.5):
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "samples": len(y_true),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0,
        "accuracy": float((y_true == y_pred).mean()),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "brier": float(brier_score_loss(y_true, y_prob)),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }

# Compute metrics
m0_all = compute_metrics(y_true_all, m0_probs)
llm_hybrid = compute_metrics(y_true_all, llm_probs)
llm_only = compute_metrics(y_true_llm, llm_only_probs)
m0_on_llm_subset = compute_metrics(y_true_llm, m0_for_llm)

print("\n" + "=" * 80)
print("TABLE: Metrics Comparison")
print("=" * 80)
header = f"{'Model':<30} {'Samples':>8} {'F1':>8} {'Prec':>8} {'Recall':>8} {'FPR':>8} {'ROC-AUC':>8} {'PR-AUC':>8}"
print(header)
print("-" * 80)
for name, m in [("M0 (all test)", m0_all), ("LLM+M0 hybrid", llm_hybrid), ("LLM only (success)", llm_only), ("M0 on LLM subset", m0_on_llm_subset)]:
    print(f"{name:<30} {m['samples']:>8} {m['f1']:.4f}   {m['precision']:.4f}   {m['recall']:.4f}   {m['fpr']:.4f}   {m['roc_auc']:.4f}   {m['pr_auc']:.4f}")

print("\n" + "=" * 80)
print("CONFUSION MATRICES")
print("=" * 80)
for name, m in [("M0 (all test)", m0_all), ("LLM only (success)", llm_only)]:
    print(f"\n  {name}: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")

# LLM analysis by label
print("\n" + "=" * 80)
print("LLM ANALYSIS BY LABEL")
print("=" * 80)
phish_results = [r for r in successful if r["label"] == 1]
legit_results = [r for r in successful if r["label"] == 0]
print(f"  Phishing: {len(phish_results)} samples")
if phish_results:
    phish_probs = [r["llm_prob"] for r in phish_results]
    print(f"    Mean prob: {np.mean(phish_probs):.4f}, Median: {np.median(phish_probs):.4f}")
    print(f"    Correct (>=0.5): {sum(1 for p in phish_probs if p >= 0.5)}/{len(phish_probs)}")
print(f"  Legitimate: {len(legit_results)} samples")
if legit_results:
    legit_probs = [r["llm_prob"] for r in legit_results]
    print(f"    Mean prob: {np.mean(legit_probs):.4f}, Median: {np.median(legit_probs):.4f}")
    print(f"    Correct (<0.5): {sum(1 for p in legit_probs if p < 0.5)}/{len(legit_probs)}")

# Error analysis
errors = [r for r in results if r["llm_prob"] is None]
print(f"\n  LLM failures: {len(errors)}")
error_kinds = {}
for r in errors:
    kind = r.get("llm_error", "unknown")
    error_kinds[kind] = error_kinds.get(kind, 0) + 1
for kind, count in sorted(error_kinds.items(), key=lambda x: -x[1]):
    print(f"    {kind}: {count}")

# Save summary
summary = {
    "benchmark_size": len(results),
    "llm_success_rate": len(successful) / len(results),
    "html_download_rate": sum(1 for r in results if r["llm_error"] != "html_download_failed") / len(results),
    "m0_all": m0_all,
    "llm_hybrid": llm_hybrid,
    "llm_only": llm_only,
    "m0_on_llm_subset": m0_on_llm_subset,
}
with open(OUTPUT / "llm_evaluation_summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
print(f"\nSummary saved to: {OUTPUT / 'llm_evaluation_summary.json'}")
