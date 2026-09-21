"""Generate LLM vs ML comparison figure."""
import json
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.stdout.reconfigure(encoding="utf-8")

OUTPUT = Path("artifacts/figures")
OUTPUT.mkdir(parents=True, exist_ok=True)
eval_dir = Path("artifacts/evaluation")

summary = json.loads((eval_dir / "llm_evaluation_summary.json").read_text())

plt.rcParams.update({
    'font.size': 11, 'axes.titlesize': 13, 'axes.labelsize': 12,
    'legend.fontsize': 9, 'figure.dpi': 150, 'savefig.bbox': 'tight',
})

# === Figure 1: Bar chart comparing M0 vs LLM ===
fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
model_names = ["M0 (all test)", "M0 on LLM subset", "LLM only (success)"]
model_keys = ["m0_all", "m0_on_llm_subset", "llm_only"]
colors = ["#1f77b4", "#1f77b4", "#d62728"]

for ax_idx, (metric, label) in enumerate([("f1", "F1 Score"), ("roc_auc", "ROC-AUC"), ("pr_auc", "PR-AUC")]):
    ax = axes[ax_idx]
    vals = [summary[k][metric] for k in model_keys]
    bars = ax.bar(range(len(model_names)), vals, color=colors, edgecolor='black', linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                f'{val:.3f}', ha='center', va='bottom', fontsize=10)
    ax.set_xticks(range(len(model_names)))
    ax.set_xticklabels(["M0\n(all)", "M0\n(LLM subset)", "LLM\n(only)"], fontsize=10)
    ax.set_ylabel(label); ax.set_title(label)
    ax.set_ylim([0, max(vals) + 0.1])
    ax.grid(True, alpha=0.3, axis='y')

fig.suptitle('LLM Agent vs ML Model (M0) — Benchmark: 100 URLs', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "llm_vs_ml.png"); fig.savefig(OUTPUT / "llm_vs_ml.pdf")
plt.close(fig)
print("OK: llm_vs_ml.png/pdf")

# === Figure 2: LLM probability distribution by label ===
results = json.loads((eval_dir / "llm_evaluation_results.json").read_text())
successful = [r for r in results if r["llm_prob"] is not None]

fig, ax = plt.subplots(figsize=(7, 5))
phish_probs = [r["llm_prob"] for r in successful if r["label"] == 1]
legit_probs = [r["llm_prob"] for r in successful if r["label"] == 0]

ax.hist(legit_probs, bins=15, alpha=0.6, color="#2ca02c", label=f'Legitimate (n={len(legit_probs)})', density=True)
ax.hist(phish_probs, bins=15, alpha=0.6, color="#d62728", label=f'Phishing (n={len(phish_probs)})', density=True)
ax.axvline(x=0.5, color='black', ls='--', lw=1.5, label='Threshold 0.5')
ax.set_xlabel('LLM Predicted Probability')
ax.set_ylabel('Density')
ax.set_title('LLM Score Distribution by Class')
ax.legend(loc='upper center', framealpha=0.9)
ax.set_xlim([-0.01, 1.01])
ax.grid(True, alpha=0.3)
fig.tight_layout()
fig.savefig(OUTPUT / "llm_distribution.png"); fig.savefig(OUTPUT / "llm_distribution.pdf")
plt.close(fig)
print("OK: llm_distribution.png/pdf")

print("\n=== Summary ===")
print(f"LLM success rate: {summary['llm_success_rate']:.1%}")
print(f"HTML download rate: {summary['html_download_rate']:.1%}")
print(f"M0 F1 (all): {summary['m0_all']['f1']:.4f}")
print(f"LLM F1 (only success): {summary['llm_only']['f1']:.4f}")
print(f"LLM is a complement for explainability, not a replacement for ML classification")
