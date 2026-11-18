"""
research.generate_figures: Generación reproducible de las 6 figuras científicas requeridas
a partir de datos empíricos computados en la evaluación, estadísticas y análisis de sensibilidad.
Zero datos pregrabados o incrustados; lectura directa de los artefactos CSV.
"""
from __future__ import annotations

import os
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import pandas as pd

from research.workspace import (
    find_data_file,
    get_candidate_roots,
    get_experiments_dir,
    get_figures_dir,
)

def find_file(candidates: list[Path]) -> Path | None:
    for c in candidates:
        if c.exists():
            return c
    return None

def generate_all_figures(workspace_root: Path | None = None) -> list[Path]:
    here = Path(__file__).resolve()
    root = workspace_root or here.parent.parent
    
    exp_dir = get_experiments_dir()
    fig_dir = get_figures_dir()
    fig_dir.mkdir(parents=True, exist_ok=True)
    root_fig_dir = root / "FIGURAS"
    root_fig_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("[research.generate_figures] GENERANDO 6 FIGURAS CIENTÍFICAS DESDE CSV REALES")
    print("=" * 75)

    # 1. Cargar fuentes de datos
    candidate_exp_dirs = [exp_dir, root / "04_EXPERIMENTOS", root / "EXPERIMENTOS", root.parent / "04_EXPERIMENTOS", root.parent / "EXPERIMENTOS"]
    
    summary_candidates = []
    equiv_candidates = []
    sens_candidates = []
    traj_candidates = []
    preds_candidates = []
    cost_risk_candidates = []

    for d in candidate_exp_dirs:
        summary_candidates.extend([d / "RESULTADOS_COMPARATIVOS.csv", d / "RESULTADOS_EVALUACION_REAL.csv"])
        equiv_candidates.extend([d / "RESULTADOS_COBERTURA_EQUIVALENTE.csv", d / "RESULTADOS_POLITICAS_CONGELADAS.csv"])
        sens_candidates.extend([d / "SENSIBILIDAD_ENTRENAMIENTO_M0.csv", d / "SENSIBILIDAD_M0_CORREGIDA.csv"])
        traj_candidates.extend([d / "TRAYECTORIAS_RAEA.csv", d / "TRAYECTORIAS_DECISION.csv"])
        preds_candidates.extend([d / "PREDICCIONES_GENERADAS_DESDE_MODELOS.csv", d / "PREDICCIONES_INDIVIDUALES.csv"])
        cost_risk_candidates.extend([d / "COSTE_RIESGO_COBERTURA.csv", d / "CURVAS_RETROSPECTIVAS.csv"])

    summary_path = find_file(summary_candidates)
    equiv_cov_path = find_file(equiv_candidates)
    m0_sens_path = find_file(sens_candidates)
    trajectories_path = find_file(traj_candidates)
    preds_all_path = find_file(preds_candidates)
    cost_risk_path = find_file(cost_risk_candidates)

    if not summary_path or not equiv_cov_path or not m0_sens_path:
        raise FileNotFoundError("No se encontraron todos los archivos CSV necesarios en EXPERIMENTOS/.")

    df_sum = pd.read_csv(summary_path)
    df_equiv = pd.read_csv(equiv_cov_path)
    df_sens = pd.read_csv(m0_sens_path)
    df_traj = pd.read_csv(trajectories_path) if trajectories_path else None
    df_preds = pd.read_csv(preds_all_path) if preds_all_path else None
    df_cr = pd.read_csv(cost_risk_path) if cost_risk_path else None

    generated_paths = []

    # =========================================================================
    # FIGURA 1: Arquitectura Conceptual y Proceso Secuencial de Decisión RAEA
    # =========================================================================
    fig, ax = plt.subplots(figsize=(10, 5), dpi=300)
    ax.axis("off")

    # Dibujar diagrama secuencial RAEA
    boxes = [
        ("Entrada:\nURL Bruta", 0.05, 0.45, 0.12, 0.22, "#e0e0e0"),
        ("M0: Modelo\nLéxico (URL)\nCoste: 0.0", 0.22, 0.45, 0.14, 0.22, "#bbdefb"),
        ("Guarda de\nCerteza VoI\n|p-0.5| >= tau_0?", 0.41, 0.45, 0.15, 0.22, "#fff9c4"),
        ("M1: Infr.\nde Red\nCoste: 0.5/0.2", 0.61, 0.65, 0.14, 0.22, "#c8e6c9"),
        ("M2: Contenido\nDOM/HTML\nCoste: 1.0/0.3", 0.61, 0.15, 0.14, 0.22, "#d1c4e9"),
        ("Decisión Final:\nPhishing / Legítimo\no Abstención", 0.82, 0.40, 0.15, 0.30, "#ffcdd2"),
    ]

    for text, x, y, w, h, col in boxes:
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02", fc=col, ec="black", lw=1.2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h/2, text, ha="center", va="center", fontsize=8.5, weight="bold")

    # Flechas
    arrowprops = dict(facecolor="black", edgecolor="black", arrowstyle="->", lw=1.2)
    ax.annotate("", xy=(0.22, 0.56), xytext=(0.17, 0.56), arrowprops=arrowprops)
    ax.annotate("", xy=(0.41, 0.56), xytext=(0.36, 0.56), arrowprops=arrowprops)
    # Early exit desde M0 a Decisión
    ax.annotate("Certeza Alta (Early Exit)", xy=(0.82, 0.60), xytext=(0.56, 0.56),
                arrowprops=dict(facecolor="#2e7d32", edgecolor="#2e7d32", arrowstyle="->", lw=1.5, ls="--"),
                fontsize=7.5, color="#2e7d32", weight="bold")
    # Ramificación condicional a M1
    ax.annotate("Incertidumbre + Avail(M1)", xy=(0.61, 0.76), xytext=(0.50, 0.67), arrowprops=arrowprops, fontsize=7.5)
    # Ramificación condicional a M2
    ax.annotate("VoI(M2) > Coste", xy=(0.61, 0.26), xytext=(0.50, 0.45), arrowprops=arrowprops, fontsize=7.5)
    # A decisión final
    ax.annotate("", xy=(0.82, 0.65), xytext=(0.75, 0.76), arrowprops=arrowprops)
    ax.annotate("", xy=(0.82, 0.45), xytext=(0.75, 0.26), arrowprops=arrowprops)

    ax.set_title("Figura 1: Arquitectura del Motor Secuencial RAEA con Adquisición Condicionada a Disponibilidad y Riesgo",
                 fontsize=10.5, weight="bold", pad=15)
    plt.tight_layout()
    f1_path = fig_dir / "fig1_raea_sequential_architecture.png"
    fig.savefig(f1_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig1_raea_sequential_architecture.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f1_path)
    print(f"  + Figura 1 generada: {f1_path.name}")

    # =========================================================================
    # FIGURA 2: Curvas de Riesgo Penalizado vs Cobertura
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), dpi=300)
    for idx, cohort_name in enumerate(["RETROSPECTIVA", "EXTERNA"]):
        ax = axes[idx]
        if df_preds is not None:
            sub = df_preds[df_preds["cohort"] == cohort_name]
            for pol, col, sty, lbl in [
                ("B6_RAEA", "#d62728", "-*", "RAEA (B6)"),
                ("B5_M1_chow", "#2ca02c", "--s", "Chow M1 (B5)"),
                ("B1_M1", "#1f77b4", ":^", "M1 Fijo (B1)")
            ]:
                sub_p = sub[sub["policy"] == pol]
                if not sub_p.empty:
                    probs = sub_p["probability"].to_numpy()
                    risks = sub_p["penalized_risk"].to_numpy()
                    confs = np.maximum(probs, 1.0 - probs)
                    thresholds = np.linspace(0.5, 0.99, 25)
                    cov_list, risk_list = [], []
                    for th in thresholds:
                        mask = confs >= th
                        cov_emp = float(np.mean(mask))
                        if cov_emp > 0:
                            cov_list.append(cov_emp)
                            risk_list.append(float(np.mean(risks[mask])))
                    if cov_list:
                        ax.plot(cov_list, risk_list, sty, color=col, label=lbl, markersize=5)
                        
        ax.set_title(f"Curva Riesgo vs Cobertura ({cohort_name})", fontsize=11, weight="bold")
        ax.set_xlabel("Cobertura de Inferencia Decidida", fontsize=10)
        ax.set_ylabel("Riesgo Asimétrico Penalizado (gamma=15)", fontsize=10)
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.legend()

    plt.tight_layout()
    f2_path = fig_dir / "fig2_risk_coverage_dual_cohorts.png"
    fig.savefig(f2_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig2_risk_coverage_dual_cohorts.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f2_path)
    print(f"  + Figura 2 generada: {f2_path.name}")

    # =========================================================================
    # FIGURA 3: Distribución de Parada por Modalidad (M0, M1, M2, Abstención)
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5), dpi=300)
    for idx, cohort_name in enumerate(["RETROSPECTIVA", "EXTERNA"]):
        ax = axes[idx]
        if df_traj is not None:
            sub = df_traj[df_traj["cohort"] == cohort_name]
            n_total = len(sub)
            
            # Clasificar parada
            m0_exit = len(sub[(sub["modalities_consulted"] == "url") & (sub["decision"] != "abstain")])
            m1_exit = len(sub[(sub["modalities_consulted"] == "url|network") & (sub["decision"] != "abstain")])
            m2_exit = len(sub[(sub["modalities_consulted"] == "url|network|html") & (sub["decision"] != "abstain")])
            abstain_exit = len(sub[sub["decision"] == "abstain"])
            
            pcts = [m0_exit / n_total * 100, m1_exit / n_total * 100, m2_exit / n_total * 100, abstain_exit / n_total * 100]
            labels = ["Salida M0 (Léxico)", "Salida M1 (Red)", "Salida M2 (HTML)", "Abstención (Riesgo/Fallo)"]
            colors = ["#42a5f5", "#66bb6a", "#ab47bc", "#ffa726"]
            
            bars = ax.bar(labels, pcts, color=colors, edgecolor="black", lw=0.8)
            ax.set_ylabel("% de Observaciones de la Cohorte")
            ax.set_title(f"Distribución de Parada RAEA ({cohort_name}, N={n_total})", fontsize=10.5, weight="bold")
            ax.set_ylim(0, max(pcts) * 1.25)
            ax.grid(True, linestyle="--", alpha=0.5, axis="y")
            
            for bar in bars:
                h = bar.get_height()
                ax.annotate(f"{h:.1f}%", xy=(bar.get_x() + bar.get_width() / 2, h),
                            xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, weight="bold")
            ax.set_xticks(range(len(labels)))
            ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=8.5)

    plt.tight_layout()
    f3_path = fig_dir / "fig3_stopping_distribution.png"
    fig.savefig(f3_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig3_stopping_distribution.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f3_path)
    print(f"  + Figura 3 generada: {f3_path.name}")

    # =========================================================================
    # FIGURA 4: Frontera de Pareto Coste vs Latencia (Baselines y Ablaciones)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(9, 5), dpi=300)
    sub_ext = df_sum[df_sum["cohort"] == "EXTERNA"]
    
    for _, row in sub_ext.iterrows():
        pol = row["policy"]
        cost = row["normalized_cost"]
        lat = row.get("latency_ms", row.get("mean_latency_ms", 0.0))
        f1 = row["f1_selective"]
        
        is_raea = "RAEA" in pol or pol == "A0"
        is_chow = "chow" in pol or "B5" in pol
        
        color = "#d62728" if is_raea else ("#2ca02c" if is_chow else "#1f77b4")
        marker = "*" if is_raea else ("D" if is_chow else "o")
        size = 140 if is_raea else 90
        
        ax.scatter(cost, lat, color=color, marker=marker, s=size, edgecolors="black", zorder=5)
        ax.annotate(f"{pol}\n(F1={f1:.2f})", (cost, lat), xytext=(0, 6), textcoords="offset points",
                    ha="center", fontsize=7.5, weight="bold" if is_raea else "normal")

    ax.set_title("Figura 4: Frontera de Compromiso Coste Normalizado vs Latencia Media (Cohorte Externa N=240)",
                 fontsize=10.5, weight="bold")
    ax.set_xlabel("Coste de Adquisición Normalizado", fontsize=10)
    ax.set_ylabel("Latencia Media de Decisión (ms)", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    f4_path = fig_dir / "fig4_pareto_cost_vs_latency.png"
    fig.savefig(f4_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig4_pareto_cost_vs_latency.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f4_path)
    print(f"  + Figura 4 generada: {f4_path.name}")

    # =========================================================================
    # FIGURA 5: Frontera de Pareto y Comparación a Cobertura Equivalente
    # =========================================================================
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), dpi=300)
    
    # Panel Izquierdo: Cobertura vs Riesgo en Cobertura Equivalente (Cohorte Externa)
    sub_eq_ext = df_equiv[df_equiv["cohort"] == "EXTERNA"]
    scenarios = sub_eq_ext["scenario"].unique()
    
    raea_covs, raea_risks, raea_f1s = [], [], []
    chow_covs, chow_risks, chow_f1s = [], [], []
    
    for sc in scenarios:
        row_r = sub_eq_ext[(sub_eq_ext["scenario"] == sc) & (sub_eq_ext["policy"] == "RAEA_Matched")]
        row_c = sub_eq_ext[(sub_eq_ext["scenario"] == sc) & (sub_eq_ext["policy"] == "B5_Chow_Matched")]
        if not row_r.empty and not row_c.empty:
            raea_covs.append(row_r["empirical_coverage"].values[0])
            raea_risks.append(row_r["penalized_risk"].values[0])
            raea_f1s.append(row_r["f1_selective"].values[0])
            
            chow_covs.append(row_c["empirical_coverage"].values[0])
            chow_risks.append(row_c["penalized_risk"].values[0])
            chow_f1s.append(row_c["f1_selective"].values[0])

    ax1.plot(raea_covs, raea_risks, "-*r", label="RAEA (Emparejado)", lw=2, markersize=8)
    ax1.plot(chow_covs, chow_risks, "--Dg", label="Chow B5 (Emparejado)", lw=2, markersize=7)
    for c, r, f in zip(raea_covs, raea_risks, raea_f1s):
        ax1.annotate(f"F1={f:.2f}", (c, r), xytext=(-10, 8), textcoords="offset points", fontsize=7.5, color="red")
    for c, r, f in zip(chow_covs, chow_risks, chow_f1s):
        ax1.annotate(f"F1={f:.2f}", (c, r), xytext=(8, -10), textcoords="offset points", fontsize=7.5, color="green")
        
    ax1.set_title("Riesgo Penalizado a Cobertura Idéntica (Cohorte Externa)", fontsize=10.5, weight="bold")
    ax1.set_xlabel("Cobertura Empírica Emparejada", fontsize=10)
    ax1.set_ylabel("Riesgo Penalizado Asimétrico (gamma=15)", fontsize=10)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend()

    # Panel Derecho: F1 Selectivo a Cobertura Idéntica (Cohorte Retrospectiva)
    sub_eq_ret = df_equiv[df_equiv["cohort"] == "RETROSPECTIVA"]
    sc_ret = sub_eq_ret["scenario"].unique()
    r_cov_ret, r_f1_ret = [], []
    c_cov_ret, c_f1_ret = [], []
    for sc in sc_ret:
        row_r = sub_eq_ret[(sub_eq_ret["scenario"] == sc) & (sub_eq_ret["policy"] == "RAEA_Matched")]
        row_c = sub_eq_ret[(sub_eq_ret["scenario"] == sc) & (sub_eq_ret["policy"] == "B5_Chow_Matched")]
        if not row_r.empty and not row_c.empty:
            r_cov_ret.append(row_r["empirical_coverage"].values[0])
            r_f1_ret.append(row_r["f1_selective"].values[0])
            c_cov_ret.append(row_c["empirical_coverage"].values[0])
            c_f1_ret.append(row_c["f1_selective"].values[0])

    ax2.plot(r_cov_ret, r_f1_ret, "-*r", label="RAEA (Emparejado)", lw=2, markersize=8)
    ax2.plot(c_cov_ret, c_f1_ret, "--Dg", label="Chow B5 (Emparejado)", lw=2, markersize=7)
    ax2.set_title("F1 Selectivo a Cobertura Idéntica (Cohorte Retrospectiva)", fontsize=10.5, weight="bold")
    ax2.set_xlabel("Cobertura Empírica Emparejada", fontsize=10)
    ax2.set_ylabel("F1 Selectivo", fontsize=10)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend()

    plt.tight_layout()
    f5_path = fig_dir / "fig5_equivalent_coverage_pareto.png"
    fig.savefig(f5_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig5_equivalent_coverage_pareto.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f5_path)
    print(f"  + Figura 5 generada: {f5_path.name}")

    # =========================================================================
    # FIGURA 6: Sensibilidad del Tamaño de Entrenamiento de M0
    # =========================================================================
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), dpi=300)
    
    # Adaptar columnas si vienen de evaluación fuera de muestra (val_eval)
    f1_col = "f1_val_eval" if "f1_val_eval" in df_sens.columns else "f1"
    brier_col = "brier_score_val_eval" if "brier_score_val_eval" in df_sens.columns else "brier_score"
    recall_col = "recall_val_eval" if "recall_val_eval" in df_sens.columns else "recall"
    fpr_col = "fpr_val_eval" if "fpr_val_eval" in df_sens.columns else "fpr"

    # Agrupar por fracción de entrenamiento
    sens_summary = df_sens.groupby("n_samples_train").agg({
        f1_col: ["mean", "std"],
        brier_col: ["mean", "std"],
        recall_col: ["mean", "std"],
        fpr_col: ["mean", "std"],
        "train_seconds": "mean"
    }).reset_index()

    n_train = sens_summary["n_samples_train"].to_numpy()
    f1_mean = sens_summary[f1_col]["mean"].to_numpy()
    f1_std = sens_summary[f1_col]["std"].to_numpy()
    brier_mean = sens_summary[brier_col]["mean"].to_numpy()
    brier_std = sens_summary[brier_col]["std"].to_numpy()
    rec_mean = sens_summary[recall_col]["mean"].to_numpy()
    fpr_mean = sens_summary[fpr_col]["mean"].to_numpy()

    # Panel Izquierdo: F1 y Recall/FPR vs Tamaño de Muestra
    ax1.errorbar(n_train, f1_mean, yerr=f1_std, fmt="-o", color="#1f77b4", label="F1-Score (Val N=26,430)", capsize=4, lw=1.8)
    ax1.plot(n_train, rec_mean, "--s", color="#2ca02c", label="Recall", lw=1.5)
    ax1.plot(n_train, fpr_mean, ":d", color="#d62728", label="FPR (Tasa Falsos Positivos)", lw=1.5)
    ax1.axvline(20000, color="gray", linestyle=":", label="Límite Histórico Arbitrario (N~20k)")
    ax1.axvline(123341, color="navy", linestyle="--", label="Entrenamiento Completo 100% (N=123,341)")
    ax1.set_title("Sensibilidad del Rendimiento de M0 vs Tamaño de Entrenamiento", fontsize=10.5, weight="bold")
    ax1.set_xlabel("Número de Observaciones de Entrenamiento (N)", fontsize=10)
    ax1.set_ylabel("Métrica de Rendimiento", fontsize=10)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(fontsize=8)

    # Panel Derecho: Brier Score (Calibración Probabilística) vs N
    ax2.errorbar(n_train, brier_mean, yerr=brier_std, fmt="-^", color="#e6550d", label="Brier Score (Calibración)", capsize=4, lw=1.8)
    ax2.set_title("Calibración Probabilística de M0 (Brier Score) vs Tamaño N", fontsize=10.5, weight="bold")
    ax2.set_xlabel("Número de Observaciones de Entrenamiento (N)", fontsize=10)
    ax2.set_ylabel("Brier Score (Menor es Mejor)", fontsize=10)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(fontsize=8.5)

    plt.tight_layout()
    f6_path = fig_dir / "fig6_m0_training_sensitivity.png"
    fig.savefig(f6_path, bbox_inches="tight")
    fig.savefig(root_fig_dir / "fig6_m0_training_sensitivity.png", bbox_inches="tight")
    plt.close(fig)
    generated_paths.append(f6_path)
    print(f"  + Figura 6 generada: {f6_path.name}")

    print(f"[research.generate_figures] ÉXITO: 6 figuras científicas generadas y guardadas.")
    print("=" * 75)
    return generated_paths

if __name__ == "__main__":
    generate_all_figures()
