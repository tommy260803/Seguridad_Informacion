"""Generate publication-quality figures for PhishGuard/PhishPe from 100% real evaluation artifacts."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import auc, average_precision_score, precision_recall_curve, roc_curve

ARTIFACTS = Path("artifacts")
EVAL_DIR = ARTIFACTS / "evaluation"
OUTPUT = ARTIFACTS / "figures"
OUTPUT.mkdir(parents=True, exist_ok=True)


def load_test_predictions(model_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    preds = []
    labels = []
    with open(model_dir / "predictions.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["partition"] == "test":
                preds.append(float(row["probability_phishing"]))
                labels.append(int(row["label"]))
    return np.array(preds, dtype=np.float64), np.array(labels, dtype=np.int8)


def main() -> None:
    model_dirs = {
        "M0": ARTIFACTS / "m0-real",
        "M1": ARTIFACTS / "m1-real",
        "M2": ARTIFACTS / "m2-real",
        "M3": ARTIFACTS / "m3-real",
        "M4": ARTIFACTS / "m4-real",
        "M5": ARTIFACTS / "m5-real",
    }
    data = {}
    for name, path in model_dirs.items():
        probs, labels = load_test_predictions(path)
        data[name] = {"probs": probs, "labels": labels}

    COLORS = {
        "M0": "#1f77b4",
        "M1": "#ff7f0e",
        "M2": "#2ca02c",
        "M3": "#d62728",
        "M4": "#9467bd",
        "M5": "#8c564b",
    }
    FEATURES = {"M0": 11, "M1": 36, "M2": 62, "M3": 75, "M4": 75, "M5": 75}

    plt.rcParams.update(
        {
            "font.size": 11,
            "axes.titlesize": 13,
            "axes.labelsize": 12,
            "legend.fontsize": 9.5,
            "figure.dpi": 200,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.1,
        }
    )

    # 1. ROC Curves (M0-M5)
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    for name in ("M0", "M1", "M2", "M3", "M4", "M5"):
        y_true = data[name]["labels"]
        y_score = data[name]["probs"]
        fpr, tpr, _ = roc_curve(y_true, y_score)
        roc_auc_val = auc(fpr, tpr)
        ax.plot(
            fpr,
            tpr,
            color=COLORS[name],
            lw=2,
            label=f"{name} ({FEATURES[name]} feat, AUC={roc_auc_val:.4f})",
        )
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.01])
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — Real Test Set (host_unseen)")
    ax.legend(loc="lower right", framealpha=0.9)
    ax.grid(True, alpha=0.3)
    fig.savefig(OUTPUT / "roc_curves.png")
    fig.savefig(OUTPUT / "roc_curves.pdf")
    plt.close(fig)

    # 2. Precision-Recall Curves (M0-M5)
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    for name in ("M0", "M1", "M2", "M3", "M4", "M5"):
        y_true = data[name]["labels"]
        y_score = data[name]["probs"]
        precision, recall, _ = precision_recall_curve(y_true, y_score)
        pr_auc_val = average_precision_score(y_true, y_score)
        ax.plot(
            recall,
            precision,
            color=COLORS[name],
            lw=2,
            label=f"{name} ({FEATURES[name]} feat, AP={pr_auc_val:.4f})",
        )
    baseline = float(data["M0"]["labels"].mean())
    ax.axhline(y=baseline, color="gray", ls="--", lw=1, alpha=0.5, label=f"Prevalence ({baseline:.2f})")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([max(0, baseline - 0.05), 1.01])
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curves — Real Test Set (host_unseen)")
    ax.legend(loc="lower left", framealpha=0.9)
    ax.grid(True, alpha=0.3)
    fig.savefig(OUTPUT / "pr_curves.png")
    fig.savefig(OUTPUT / "pr_curves.pdf")
    plt.close(fig)

    # 3. Calibration Curves (M0-M3, M5)
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    n_bins = 15
    for name in ("M0", "M1", "M2", "M3"):
        y_true = data[name]["labels"]
        y_score = data[name]["probs"]
        bin_edges = np.linspace(0, 1, n_bins + 1)
        bin_means, bin_true_means, bin_counts = [], [], []
        for i in range(n_bins):
            mask = (y_score >= bin_edges[i]) & (
                y_score < bin_edges[i + 1] if i < n_bins - 1 else y_score <= bin_edges[i + 1]
            )
            if mask.sum() > 0:
                bin_means.append(float(y_score[mask].mean()))
                bin_true_means.append(float(y_true[mask].mean()))
                bin_counts.append(int(mask.sum()))
        bm = np.array(bin_means)
        bt = np.array(bin_true_means)
        bc = np.array(bin_counts)
        ece = float(np.sum(np.abs(bt - bm) * bc) / bc.sum())
        ax.plot(bm, bt, "o-", color=COLORS[name], lw=2, markersize=5, label=f"{name} (ECE={ece:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Perfect calibration")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.01])
    ax.set_xlabel("Mean Predicted Probability")
    ax.set_ylabel("Empirical Fraction of Positives")
    ax.set_title("Reliability Diagrams — Real Test Set (host_unseen)")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, alpha=0.3)
    fig.savefig(OUTPUT / "calibration_curves.png")
    fig.savefig(OUTPUT / "calibration_curves.pdf")
    plt.close(fig)

    # 4. Confusion Matrices (M0, M1, M2, M3)
    fig, axes = plt.subplots(1, 4, figsize=(17, 4.2))
    for idx, name in enumerate(("M0", "M1", "M2", "M3")):
        m_json = json.loads((ARTIFACTS / f"{name.lower()}-real" / "metrics.json").read_text(encoding="utf-8"))
        cm_dict = m_json["partitions"]["test"]["selected_threshold"]["confusion_matrix"]
        tn, fp, fn, tp = cm_dict["tn"], cm_dict["fp"], cm_dict["fn"], cm_dict["tp"]
        cm = np.array([[tn, fp], [fn, tp]])
        cm_pct = cm / cm.sum() * 100.0
        ax = axes[idx]
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=cm.max())
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Legit", "Phish"])
        ax.set_yticklabels(["Legit", "Phish"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title(f"{name} ({FEATURES[name]} feat)")
        for i in range(2):
            for j in range(2):
                color = "white" if cm[i, j] > cm.max() / 2 else "black"
                ax.text(j, i, f"{cm[i, j]:,}\n({cm_pct[i, j]:.1f}%)", ha="center", va="center", color=color, fontsize=9.5)
    fig.suptitle("Confusion Matrices — Real Test Set (host_unseen)", fontsize=13, y=1.03)
    fig.tight_layout()
    fig.savefig(OUTPUT / "confusion_matrices.png")
    fig.savefig(OUTPUT / "confusion_matrices.pdf")
    plt.close(fig)

    # 5. Coverage-Risk Curve (M0, M1, M2, M3, M5)
    cr_path = EVAL_DIR / "coverage_risk_curves_real.csv"
    if cr_path.exists():
        cr_by_model: dict[str, list[tuple[float, float]]] = {}
        with open(cr_path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                cov = float(row["coverage"])
                risk = float(row["selective_risk"])
                if cov > 0.15:
                    cr_by_model.setdefault(row["model"], []).append((cov, risk))
        fig, ax = plt.subplots(figsize=(7.5, 5.2))
        for m_name, pts in cr_by_model.items():
            pts_sorted = sorted(pts, key=lambda x: x[0])
            ax.plot(
                [p[0] for p in pts_sorted],
                [p[1] for p in pts_sorted],
                "o-",
                color=COLORS.get(m_name, "#333333"),
                lw=2,
                markersize=4,
                label=m_name,
            )
        ax.set_xlabel("Coverage (Fraction of Decided Samples)")
        ax.set_ylabel("Selective Risk (Error Rate on Decided Samples)")
        ax.set_title("Selective Classification Coverage-Risk Curves — Real Test Set")
        ax.legend(loc="upper left")
        ax.grid(True, alpha=0.3)
        fig.savefig(OUTPUT / "coverage_risk_curves.png")
        fig.savefig(OUTPUT / "coverage_risk_curves.pdf")
        plt.close(fig)

    # 6. Summary Bar Chart (M0-M5 F1, PR-AUC, ROC-AUC)
    eval_sum = json.loads((EVAL_DIR / "evaluation_summary_real.json").read_text(encoding="utf-8"))
    cc_models = eval_sum["multimodal_cohort"]["host_unseen"]["complete_case"]["models"]
    names_bar = ["M0", "M1", "M2", "M3", "M4", "M5"]
    f1_vals = [
        cc_models[n]["test_selective_metrics"]["f1"] if n == "M5" else cc_models[n]["test_metrics"]["f1"]
        for n in names_bar
    ]
    roc_vals = [
        cc_models[n]["test_full_metrics"]["roc_auc"] if n == "M5" else cc_models[n]["test_metrics"]["roc_auc"]
        for n in names_bar
    ]
    pr_vals = [
        cc_models[n]["test_full_metrics"]["pr_auc"] if n == "M5" else cc_models[n]["test_metrics"]["pr_auc"]
        for n in names_bar
    ]

    fig, axes = plt.subplots(1, 3, figsize=(14.5, 4.5))
    for ax_idx, (vals, label) in enumerate([(f1_vals, "F1 Score"), (pr_vals, "PR-AUC"), (roc_vals, "ROC-AUC")]):
        ax = axes[ax_idx]
        bars = ax.bar(names_bar, vals, color=[COLORS[n] for n in names_bar], edgecolor="black", linewidth=0.5)
        for bar, val in zip(bars, vals):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.003,
                f"{val:.3f}",
                ha="center",
                va="bottom",
                fontsize=9,
            )
        ax.set_ylabel(label)
        ax.set_title(label)
        ax.set_ylim([min(vals) - 0.04, min(1.02, max(vals) + 0.03)])
        ax.grid(True, alpha=0.3, axis="y")
    fig.suptitle("Real Multimodal Cohort Performance Comparison (M0–M5, host_unseen)", fontsize=13, y=1.02)
    fig.tight_layout()
    fig.savefig(OUTPUT / "performance_comparison.png")
    fig.savefig(OUTPUT / "performance_comparison.pdf")
    plt.close(fig)

    # 7. Adversarial Robustness Bar Chart
    rob_path = EVAL_DIR / "robustness_evaluation_real.json"
    if rob_path.exists():
        rob = json.loads(rob_path.read_text(encoding="utf-8"))
        atks = list(rob["attacks"].keys())
        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(atks))
        width = 0.25
        for offset, m_key in [(-width, "M0"), (0.0, "M3"), (width, "M5")]:
            recs = [rob["attacks"][a]["models"][m_key]["perturbed_recall"] for a in atks]
            ax.bar(x + offset, recs, width=width, color=COLORS[m_key], edgecolor="black", linewidth=0.5, label=m_key)
        ax.set_xticks(x)
        ax.set_xticklabels([a.replace("_", "\n") for a in atks], fontsize=9.5)
        ax.set_ylabel("Post-Attack Phishing Recall")
        ax.set_ylim([0, 1.05])
        ax.set_title("Adversarial Recall Resilience Across Attack Vectors (M0 vs M3 vs M5)")
        ax.legend()
        ax.grid(True, alpha=0.3, axis="y")
        fig.tight_layout()
        fig.savefig(OUTPUT / "adversarial_robustness.png")
        fig.savefig(OUTPUT / "adversarial_robustness.pdf")
        plt.close(fig)

    print("All real figures generated successfully in artifacts/figures/!", flush=True)


if __name__ == "__main__":
    main()
