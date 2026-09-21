"""Generate publication figures comparing M0 with real-analysis M1-M3."""
import csv
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score
import joblib

ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "figures"
OUTPUT.mkdir(parents=True, exist_ok=True)


def load_test_predictions(model_dir):
    preds, labels = [], []
    with open(model_dir / "predictions.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["partition"] == "test":
                preds.append(float(row["probability_phishing"]))
                labels.append(int(row["label"]))
    return np.array(preds), np.array(labels)


models = {
    "M0 (URL)": ARTIFACTS / "url-baseline-0.2.0",
    "M1 (URL+Infra)": ARTIFACTS / "m1-real",
    "M2 (URL+Infra+Content)": ARTIFACTS / "m2-real",
}
COLORS = {"M0 (URL)": "#1f77b4", "M1 (URL+Infra)": "#ff7f0e", "M2 (URL+Infra+Content)": "#2ca02c"}
FEATURES = {"M0 (URL)": 11, "M1 (URL+Infra)": 29, "M2 (URL+Infra+Content)": 50}

data = {}
for name, path in models.items():
    probs, labels = load_test_predictions(path)
    data[name] = {"probs": probs, "labels": labels}

plt.rcParams.update({
    'font.size': 11, 'axes.titlesize': 13, 'axes.labelsize': 12,
    'legend.fontsize': 9, 'figure.dpi': 150, 'savefig.bbox': 'tight',
})

# === FIGURE 1: ROC Curves ===
fig, ax = plt.subplots(figsize=(7, 5.5))
for name in models:
    y_true, y_score = data[name]["labels"], data[name]["probs"]
    fpr, tpr, _ = roc_curve(y_true, y_score)
    ax.plot(fpr, tpr, color=COLORS[name], lw=2,
            label=f'{name} (AUC={auc(fpr, tpr):.3f})')
ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Random')
ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — Test Set (host_unseen, real analysis)')
ax.legend(loc='lower right', framealpha=0.9); ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "roc_real.png"); fig.savefig(OUTPUT / "roc_real.pdf")
plt.close(fig)
print("OK: roc_real.png/pdf")

# === FIGURE 2: PR Curves ===
fig, ax = plt.subplots(figsize=(7, 5.5))
for name in models:
    y_true, y_score = data[name]["labels"], data[name]["probs"]
    precision, recall, _ = precision_recall_curve(y_true, y_score)
    ap = average_precision_score(y_true, y_score)
    ax.plot(recall, precision, color=COLORS[name], lw=2, label=f'{name} (AP={ap:.3f})')
baseline = data["M0 (URL)"]["labels"].mean()
ax.axhline(y=baseline, color='gray', ls='--', lw=1, alpha=0.5, label=f'Baseline ({baseline:.2f})')
ax.set_xlabel('Recall'); ax.set_ylabel('Precision')
ax.set_title('Precision-Recall Curves — Test Set (real analysis)')
ax.legend(loc='lower left', framealpha=0.9); ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "pr_real.png"); fig.savefig(OUTPUT / "pr_real.pdf")
plt.close(fig)
print("OK: pr_real.png/pdf")

# === FIGURE 3: Calibration ===
fig, ax = plt.subplots(figsize=(7, 5.5))
n_bins = 15
for name in models:
    y_true, y_score = data[name]["labels"], data[name]["probs"]
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_means, bin_true, bin_counts = [], [], []
    for i in range(n_bins):
        mask = (y_score >= bin_edges[i]) & (y_score < bin_edges[i + 1] if i < n_bins - 1 else y_score <= bin_edges[i + 1])
        if mask.sum() > 0:
            bin_means.append(y_score[mask].mean())
            bin_true.append(y_true[mask].mean())
            bin_counts.append(mask.sum())
    bin_means, bin_true, bin_counts = np.array(bin_means), np.array(bin_true), np.array(bin_counts)
    ece = np.sum(np.abs(bin_true - bin_means) * bin_counts) / bin_counts.sum()
    ax.plot(bin_means, bin_true, 'o-', color=COLORS[name], lw=2, markersize=5, label=f'{name} (ECE={ece:.3f})')
ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Perfect')
ax.set_xlabel('Mean Predicted Probability'); ax.set_ylabel('Fraction of Positives')
ax.set_title('Calibration Curves — Test Set (real analysis)')
ax.legend(loc='upper left', framealpha=0.9); ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "calibration_real.png"); fig.savefig(OUTPUT / "calibration_real.pdf")
plt.close(fig)
print("OK: calibration_real.png/pdf")

# === FIGURE 4: Performance Comparison Bar Chart ===
fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
model_names = list(models.keys())
metrics_data = {}
for name in model_names:
    m = json.loads((models[name] / "metrics.json").read_text())
    metrics_data[name] = m["partitions"]["test"]["selected_threshold"]

for ax_idx, (metric, label) in enumerate([("f1", "F1 Score"), ("pr_auc", "PR-AUC"), ("roc_auc", "ROC-AUC")]):
    ax = axes[ax_idx]
    vals = [metrics_data[n][metric] for n in model_names]
    bars = ax.bar(range(len(model_names)), vals, color=[COLORS[n] for n in model_names], edgecolor='black', linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001, f'{val:.4f}', ha='center', va='bottom', fontsize=9)
    ax.set_xticks(range(len(model_names)))
    ax.set_xticklabels([n.split("(")[0].strip() for n in model_names], fontsize=10)
    ax.set_ylabel(label); ax.set_title(label)
    ax.set_ylim([min(vals) - 0.02, max(vals) + 0.015])
    ax.grid(True, alpha=0.3, axis='y')
fig.suptitle('Test Set Performance — Real Analysis Results', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "performance_real.png"); fig.savefig(OUTPUT / "performance_real.pdf")
plt.close(fig)
print("OK: performance_real.png/pdf")

# === FIGURE 5: Delta Bar Chart ===
fig, ax = plt.subplots(figsize=(8, 5))
metric_names = ["f1", "precision", "recall", "false_positive_rate", "pr_auc", "roc_auc", "brier_score", "expected_calibration_error"]
m0_vals = {m: metrics_data["M0 (URL)"][m] for m in metric_names}
x = np.arange(len(metric_names))
width = 0.25
for i, name in enumerate(["M1 (URL+Infra)", "M2 (URL+Infra+Content)"]):
    deltas = [metrics_data[name][m] - m0_vals[m] for m in metric_names]
    bars = ax.bar(x + i * width, deltas, width, label=name, color=COLORS[name], edgecolor='black', linewidth=0.5)
ax.axhline(y=0, color='black', lw=1)
ax.set_xticks(x + width / 2)
ax.set_xticklabels([m.replace('_', '\n') for m in metric_names], fontsize=9)
ax.set_ylabel('Delta vs M0 (positive = better)')
ax.set_title('Feature Contribution Analysis (Real Results)')
ax.legend(loc='best', framealpha=0.9); ax.grid(True, alpha=0.3, axis='y')
fig.tight_layout()
fig.savefig(OUTPUT / "delta_real.png"); fig.savefig(OUTPUT / "delta_real.pdf")
plt.close(fig)
print("OK: delta_real.png/pdf")

print(f"\n=== All figures saved to {OUTPUT} ===")
