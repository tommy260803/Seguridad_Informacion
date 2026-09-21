"""Generate temporal vs host_unseen comparison figures."""
import csv
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score

ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "figures"
OUTPUT.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    'font.size': 11, 'axes.titlesize': 13, 'axes.labelsize': 12,
    'legend.fontsize': 9, 'figure.dpi': 150, 'savefig.bbox': 'tight',
})


def load_test_preds(model_dir):
    preds, labels = [], []
    with open(model_dir / "predictions.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["partition"] == "test":
                preds.append(float(row["probability_phishing"]))
                labels.append(int(row["label"]))
    return np.array(preds), np.array(labels)


# Load predictions
hun_probs, hun_labels = load_test_preds(ARTIFACTS / "url-baseline-0.2.0")
tmp_probs, tmp_labels = load_test_preds(ARTIFACTS / "m0-temporal")

# Load metrics
hun_m = json.loads(open("artifacts/url-baseline-0.2.0/metrics.json").read())["partitions"]["test"]["selected_threshold"]
tmp_m = json.loads(open("artifacts/m0-temporal/metrics.json").read())["partitions"]["test"]["selected_threshold"]

COLORS = {"host_unseen": "#1f77b4", "temporal": "#d62728"}

# === FIGURE 1: Side-by-side ROC ===
fig, axes = plt.subplots(1, 2, figsize=(13, 5))

# Left: ROC
ax = axes[0]
for name, probs, labels in [("host_unseen", hun_probs, hun_labels), ("temporal", tmp_probs, tmp_labels)]:
    fpr, tpr, _ = roc_curve(labels, probs)
    roc_auc_val = auc(fpr, tpr)
    ax.plot(fpr, tpr, color=COLORS[name], lw=2,
            label=f'{name} (AUC={roc_auc_val:.3f})')
ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5)
ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — M0')
ax.legend(loc='lower right', framealpha=0.9); ax.grid(True, alpha=0.3)

# Right: PR
ax = axes[1]
for name, probs, labels in [("host_unseen", hun_probs, hun_labels), ("temporal", tmp_probs, tmp_labels)]:
    precision, recall, _ = precision_recall_curve(labels, probs)
    ap = average_precision_score(labels, probs)
    ax.plot(recall, precision, color=COLORS[name], lw=2, label=f'{name} (AP={ap:.3f})')
ax.set_xlabel('Recall'); ax.set_ylabel('Precision')
ax.set_title('PR Curves — M0')
ax.legend(loc='lower left', framealpha=0.9); ax.grid(True, alpha=0.3)

fig.suptitle('M0 Performance: host_unseen vs Temporal Split', fontsize=14, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "temporal_roc_pr.png"); fig.savefig(OUTPUT / "temporal_roc_pr.pdf")
plt.close(fig)
print("OK: temporal_roc_pr.png/pdf")

# === FIGURE 2: Bar chart comparison ===
fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
metrics_to_plot = [("f1", "F1 Score"), ("pr_auc", "PR-AUC"), ("roc_auc", "ROC-AUC")]

for ax_idx, (metric, label) in enumerate(metrics_to_plot):
    ax = axes[ax_idx]
    hun_val = hun_m[metric]
    tmp_val = tmp_m[metric]
    bars = ax.bar(["host_unseen", "temporal"], [hun_val, tmp_val],
                  color=[COLORS["host_unseen"], COLORS["temporal"]],
                  edgecolor='black', linewidth=0.5)
    for bar, val in zip(bars, [hun_val, tmp_val]):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
                f'{val:.4f}', ha='center', va='bottom', fontsize=10)
    delta = tmp_val - hun_val
    ax.text(0.5, max(hun_val, tmp_val) * 0.5, f'{delta:+.4f}',
            ha='center', va='center', fontsize=11, fontweight='bold',
            color='red' if delta < 0 else 'green',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
    ax.set_ylabel(label); ax.set_title(label)
    ax.set_ylim([min(hun_val, tmp_val) - 0.03, max(hun_val, tmp_val) + 0.02])
    ax.grid(True, alpha=0.3, axis='y')

fig.suptitle('Temporal Generalization Gap — M0', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "temporal_comparison.png"); fig.savefig(OUTPUT / "temporal_comparison.pdf")
plt.close(fig)
print("OK: temporal_comparison.png/pdf")

# === FIGURE 3: Score distributions ===
fig, axes = plt.subplots(1, 2, figsize=(13, 5))
for ax, (name, probs, labels) in zip(axes, [("host_unseen", hun_probs, hun_labels), ("temporal", tmp_probs, tmp_labels)]):
    ax.hist(probs[labels == 0], bins=50, alpha=0.6, color="#2ca02c", label='Legitimate', density=True)
    ax.hist(probs[labels == 1], bins=50, alpha=0.6, color="#d62728", label='Phishing', density=True)
    ax.axvline(x=0.5, color='black', ls='--', lw=1, alpha=0.7, label='Threshold 0.5')
    ax.set_xlabel('Predicted Probability'); ax.set_ylabel('Density')
    ax.set_title(f'Score Distribution — {name}')
    ax.legend(loc='upper center', fontsize=9); ax.set_xlim([-0.01, 1.01])

fig.suptitle('M0 Score Distributions by Split', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "temporal_distributions.png"); fig.savefig(OUTPUT / "temporal_distributions.pdf")
plt.close(fig)
print("OK: temporal_distributions.png/pdf")

# === Summary table ===
print("\n" + "=" * 70)
print("SUMMARY: Temporal Generalization Gap")
print("=" * 70)
print(f"{'Metric':<30} {'host_unseen':>12} {'temporal':>12} {'Delta':>12}")
print("-" * 70)
for metric in ["f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error"]:
    hun_val = hun_m[metric]
    tmp_val = tmp_m[metric]
    delta = tmp_val - hun_val
    print(f"{metric:<30} {hun_val:>12.4f} {tmp_val:>12.4f} {delta:>+12.4f}")
