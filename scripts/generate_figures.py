"""Generate publication-quality figures for PhishGuard evaluation."""
import csv
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
from pathlib import Path
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score

ARTIFACTS = Path("artifacts")
OUTPUT = ARTIFACTS / "figures"
OUTPUT.mkdir(parents=True, exist_ok=True)

# Load predictions for all models
def load_test_predictions(model_dir):
    """Load test partition predictions from CSV."""
    preds = []
    labels = []
    with open(model_dir / "predictions.csv", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["partition"] == "test":
                preds.append(float(row["probability_phishing"]))
                labels.append(int(row["label"]))
    return np.array(preds), np.array(labels)

models = {
    "M0": ARTIFACTS / "url-baseline-0.2.0",
    "M1": ARTIFACTS / "m1-baseline",
    "M2": ARTIFACTS / "m2-baseline",
}
# M3 doesn't have predictions.csv, skip for plots

data = {}
for name, path in models.items():
    probs, labels = load_test_predictions(path)
    data[name] = {"probs": probs, "labels": labels}

# Colors
COLORS = {"M0": "#1f77b4", "M1": "#ff7f0e", "M2": "#2ca02c", "M3": "#d62728"}
FEATURES = {"M0": 11, "M1": 29, "M2": 50, "M3": 59}

plt.rcParams.update({
    'font.size': 11,
    'axes.titlesize': 13,
    'axes.labelsize': 12,
    'legend.fontsize': 10,
    'figure.dpi': 150,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
})

# ============================================================
# FIGURE 1: ROC Curves
# ============================================================
fig, ax = plt.subplots(figsize=(7, 5.5))
for name in ["M0", "M1", "M2"]:
    y_true = data[name]["labels"]
    y_score = data[name]["probs"]
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc_val = auc(fpr, tpr)
    ax.plot(fpr, tpr, color=COLORS[name], lw=2,
            label=f'{name} ({FEATURES[name]} feat, AUC={roc_auc_val:.3f})')

ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Random')
ax.set_xlim([-0.01, 1.01])
ax.set_ylim([-0.01, 1.01])
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — Test Set (host_unseen)')
ax.legend(loc='lower right', framealpha=0.9)
ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "roc_curves.png")
fig.savefig(OUTPUT / "roc_curves.pdf")
plt.close(fig)
print("OK: roc_curves.png/pdf")

# ============================================================
# FIGURE 2: Precision-Recall Curves
# ============================================================
fig, ax = plt.subplots(figsize=(7, 5.5))
for name in ["M0", "M1", "M2"]:
    y_true = data[name]["labels"]
    y_score = data[name]["probs"]
    precision, recall, _ = precision_recall_curve(y_true, y_score)
    pr_auc_val = average_precision_score(y_true, y_score)
    ax.plot(recall, precision, color=COLORS[name], lw=2,
            label=f'{name} ({FEATURES[name]} feat, AP={pr_auc_val:.3f})')

baseline = data["M0"]["labels"].mean()
ax.axhline(y=baseline, color='gray', ls='--', lw=1, alpha=0.5, label=f'Baseline ({baseline:.2f})')
ax.set_xlim([-0.01, 1.01])
ax.set_ylim([max(0, baseline - 0.05), 1.01])
ax.set_xlabel('Recall')
ax.set_ylabel('Precision')
ax.set_title('Precision-Recall Curves — Test Set (host_unseen)')
ax.legend(loc='lower left', framealpha=0.9)
ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "pr_curves.png")
fig.savefig(OUTPUT / "pr_curves.pdf")
plt.close(fig)
print("OK: pr_curves.png/pdf")

# ============================================================
# FIGURE 3: Calibration Curves (Reliability Diagram)
# ============================================================
fig, ax = plt.subplots(figsize=(7, 5.5))
n_bins = 15
for name in ["M0", "M1", "M2"]:
    y_true = data[name]["labels"]
    y_score = data[name]["probs"]
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_means = []
    bin_true_means = []
    bin_counts = []
    for i in range(n_bins):
        mask = (y_score >= bin_edges[i]) & (y_score < bin_edges[i + 1] if i < n_bins - 1 else y_score <= bin_edges[i + 1])
        if mask.sum() > 0:
            bin_means.append(y_score[mask].mean())
            bin_true_means.append(y_true[mask].mean())
            bin_counts.append(mask.sum())
    bin_means = np.array(bin_means)
    bin_true_means = np.array(bin_true_means)
    bin_counts = np.array(bin_counts)
    ece = np.sum(np.abs(bin_true_means - bin_means) * bin_counts) / bin_counts.sum()
    ax.plot(bin_means, bin_true_means, 'o-', color=COLORS[name], lw=2, markersize=5,
            label=f'{name} (ECE={ece:.3f})')

ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Perfect calibration')
ax.set_xlim([-0.01, 1.01])
ax.set_ylim([-0.01, 1.01])
ax.set_xlabel('Mean Predicted Probability')
ax.set_ylabel('Fraction of Positives')
ax.set_title('Calibration Curves — Test Set (host_unseen)')
ax.legend(loc='upper left', framealpha=0.9)
ax.grid(True, alpha=0.3)
fig.savefig(OUTPUT / "calibration_curves.png")
fig.savefig(OUTPUT / "calibration_curves.pdf")
plt.close(fig)
print("OK: calibration_curves.png/pdf")

# ============================================================
# FIGURE 4: Confusion Matrix Heatmaps
# ============================================================
fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
for idx, name in enumerate(["M0", "M1", "M2"]):
    y_true = data[name]["labels"]
    y_pred = (data[name]["probs"] >= 0.5).astype(int)
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    cm = np.array([[tn, fp], [fn, tp]])
    cm_pct = cm / cm.sum() * 100

    ax = axes[idx]
    im = ax.imshow(cm, cmap='Blues', vmin=0, vmax=cm.max())
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Legit', 'Phish'])
    ax.set_yticklabels(['Legit', 'Phish'])
    ax.set_xlabel('Predicted')
    ax.set_ylabel('Actual')
    ax.set_title(f'{name} ({FEATURES[name]} feat)')

    for i in range(2):
        for j in range(2):
            color = 'white' if cm[i, j] > cm.max() / 2 else 'black'
            ax.text(j, i, f'{cm[i, j]:,}\n({cm_pct[i, j]:.1f}%)',
                    ha='center', va='center', color=color, fontsize=10)

fig.suptitle('Confusion Matrices — Test Set (threshold=0.5)', fontsize=13, y=1.02)
fig.colorbar(im, ax=axes, shrink=0.8, label='Count')
fig.tight_layout()
fig.savefig(OUTPUT / "confusion_matrices.png")
fig.savefig(OUTPUT / "confusion_matrices.pdf")
plt.close(fig)
print("OK: confusion_matrices.png/pdf")

# ============================================================
# FIGURE 5: Probability Distribution by Class
# ============================================================
fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
for idx, name in enumerate(["M0", "M1", "M2"]):
    y_true = data[name]["labels"]
    y_score = data[name]["probs"]
    ax = axes[idx]
    ax.hist(y_score[y_true == 0], bins=50, alpha=0.6, color=COLORS["M0"], label='Legitimate', density=True)
    ax.hist(y_score[y_true == 1], bins=50, alpha=0.6, color=COLORS["M3"], label='Phishing', density=True)
    ax.axvline(x=0.5, color='black', ls='--', lw=1, alpha=0.7, label='Threshold')
    ax.set_xlabel('Predicted Probability')
    ax.set_ylabel('Density')
    ax.set_title(f'{name} ({FEATURES[name]} feat)')
    ax.legend(loc='upper center', fontsize=9)
    ax.set_xlim([-0.01, 1.01])

fig.suptitle('Score Distribution by Class — Test Set', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "score_distributions.png")
fig.savefig(OUTPUT / "score_distributions.pdf")
plt.close(fig)
print("OK: score_distributions.png/pdf")

# ============================================================
# FIGURE 6: Feature Importance (M0)
# ============================================================
import joblib
m0 = joblib.load(ARTIFACTS / "url-baseline-0.2.0/conventional/model.joblib")
model = m0["model"]
feature_names = m0["feature_names"]

# Get feature importances from HistGradientBoosting
base = model
if hasattr(model, 'calibrated_classifiers_'):
    base = model.calibrated_classifiers_[0].estimator
# HistGradientBoosting uses feature_importances_ after fit
importances = base.feature_importances_ if hasattr(base, 'feature_importances_') else np.ones(len(feature_names)) / len(feature_names)

# Sort by importance
sorted_idx = np.argsort(importances)
fig, ax = plt.subplots(figsize=(7, 5))
ax.barh(np.array(feature_names)[sorted_idx], importances[sorted_idx], color=COLORS["M0"])
ax.set_xlabel('Feature Importance (Gini)')
ax.set_title('M0 Feature Importance (URL-only baseline)')
ax.grid(True, alpha=0.3, axis='x')
fig.savefig(OUTPUT / "m0_feature_importance.png")
fig.savefig(OUTPUT / "m0_feature_importance.pdf")
plt.close(fig)
print("OK: m0_feature_importance.png/pdf")

# ============================================================
# FIGURE 7: Summary Bar Chart
# ============================================================
fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
model_names = ["M0", "M1", "M2"]
feat_counts = [FEATURES[n] for n in model_names]

# Load metrics
metrics_data = {}
for name in model_names:
    import json
    metrics_path = ARTIFACTS / ("url-baseline-0.2.0" if name == "M0" else f"{name.lower()}-baseline") / "metrics.json"
    m = json.loads(metrics_path.read_text(encoding="utf-8"))
    t = m["partitions"]["test"]["selected_threshold"]
    metrics_data[name] = t

# F1, PR-AUC, ROC-AUC
bar_metrics = [("f1", "F1 Score"), ("pr_auc", "PR-AUC"), ("roc_auc", "ROC-AUC")]
for ax_idx, (metric, label) in enumerate(bar_metrics):
    ax = axes[ax_idx]
    vals = [metrics_data[n][metric] for n in model_names]
    bars = ax.bar(model_names, vals, color=[COLORS[n] for n in model_names], edgecolor='black', linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
                f'{val:.3f}', ha='center', va='bottom', fontsize=10)
    ax.set_ylabel(label)
    ax.set_title(label)
    ax.set_ylim([min(vals) - 0.05, max(vals) + 0.03])
    ax.grid(True, alpha=0.3, axis='y')

fig.suptitle('Test Set Performance Comparison', fontsize=13, y=1.02)
fig.tight_layout()
fig.savefig(OUTPUT / "performance_comparison.png")
fig.savefig(OUTPUT / "performance_comparison.pdf")
plt.close(fig)
print("OK: performance_comparison.png/pdf")

# List all generated figures
print("\n=== Generated Figures ===")
for f in sorted(OUTPUT.glob("*.png")):
    print(f"  {f}")
print(f"\nTotal: {len(list(OUTPUT.glob('*.png')))} PNG + {len(list(OUTPUT.glob('*.pdf')))} PDF files")
