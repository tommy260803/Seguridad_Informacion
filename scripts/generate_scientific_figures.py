"""
Genera las 4 figuras científicas obligatorias para el paquete final de RAEA-Phish:
1. FIGURAS/fig1_cost_coverage_tradeoff.png: Compromiso entre coste normalizado y cobertura.
2. FIGURAS/fig2_risk_vs_coverage.png: Riesgo selectivo penalizado frente a cobertura.
3. FIGURAS/fig3_policy_comparison.png: Comparación multidimensional de políticas (M1, B5, RAEA, etc.).
4. FIGURAS/fig4_ablations_analysis.png: Efecto de cada ablación (A1-A6) sobre F1, riesgo y coste.
"""

from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "artifacts" / "raea_final"
FIG_DIR = DATA_DIR / "FIGURAS"
FIG_DIR.mkdir(parents=True, exist_ok=True)

# Estilo científico limpio
plt.rcParams.update({
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "figure.titlesize": 13,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})


def plot_cost_coverage(df_res: pd.DataFrame):
    """Figura 1: Compromiso Coste vs Cobertura en PHISHING_WEB_TEST (N=118)."""
    pw = df_res[df_res["population"] == "PHISHING_WEB_TEST"].copy()
    
    # Políticas clave a graficar
    plot_pols = [
        ("B0_M0", "B0: M0 Léxico", "gray", "o"),
        ("B1_M1", "B1: M1 Red", "#1f77b4", "s"),
        ("B2_M2", "B2: M2 Contenido", "#ff7f0e", "^"),
        ("B3_entropy", "B3: Cascada Entropía", "#2ca02c", "D"),
        ("B5_M1_chow", "B5: Selectiva Chow (M1)", "#9467bd", "v"),
        ("B6_RAEA", "B6: RAEA Completo", "#d62728", "*"),
    ]
    
    fig, ax = plt.subplots(figsize=(7, 4.5))
    
    for pol_id, label, color, marker in plot_pols:
        sub = pw[pw["policy"] == pol_id]
        if sub.empty:
            continue
        cov = sub["coverage"].values[0] * 100.0
        cost = sub["mean_normalized_cost"].values[0]
        size = 180 if pol_id == "B6_RAEA" else 100
        ax.scatter(cov, cost, color=color, marker=marker, s=size, label=label, zorder=5)
        
        # Offset para etiquetas de texto
        dx = -3 if pol_id == "B6_RAEA" else (2 if cov > 90 else -5)
        dy = 0.04 if pol_id == "B1_M1" else (-0.05 if pol_id == "B5_M1_chow" else 0.03)
        ax.annotate(pol_id.split("_")[0], (cov, cost), textcoords="offset points", xytext=(dx*4, dy*100),
                    fontsize=8, fontweight="bold" if pol_id == "B6_RAEA" else "normal")

    ax.set_xlabel("Cobertura Operacional (%)")
    ax.set_ylabel("Coste Normalizado Medio de Adquisición")
    ax.set_title("Compromiso Coste-Cobertura (Población: Phishing Web, N=118)")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(loc="upper left", frameon=True)
    ax.set_xlim(65, 105)
    ax.set_ylim(-0.05, 1.45)
    
    fig.savefig(FIG_DIR / "fig1_cost_coverage_tradeoff.png")
    plt.close(fig)
    print("-> Generada: FIGURAS/fig1_cost_coverage_tradeoff.png")


def plot_risk_coverage(df_res: pd.DataFrame):
    """Figura 2: Riesgo Selectivo Penalizado frente a Cobertura."""
    pw = df_res[df_res["population"] == "PHISHING_WEB_TEST"].copy()
    
    plot_pols = [
        ("B1_M1", "B1: M1 Fijo (100% cov)", "#1f77b4", "s"),
        ("B1_M1_bayes", "B1_bayes: M1 Umbral Bayes", "#17becf", "P"),
        ("B3_entropy", "B3: Cascada Entropía", "#2ca02c", "D"),
        ("B4_conservative", "B4: Cascada Conservadora", "#bcbd22", "h"),
        ("B5_M1_chow", "B5: Chow sobre M1", "#9467bd", "v"),
        ("B5_M1_cov_pw", "B5_cov: Cobertura Igualada", "#8c564b", "X"),
        ("B6_RAEA", "B6: RAEA Completo", "#d62728", "*"),
    ]
    
    fig, ax = plt.subplots(figsize=(7, 4.5))
    
    for pol_id, label, color, marker in plot_pols:
        sub = pw[pw["policy"] == pol_id]
        if sub.empty:
            continue
        cov = sub["coverage"].values[0] * 100.0
        risk = sub["risk_selective_penalized"].values[0]
        size = 180 if pol_id == "B6_RAEA" else 100
        ax.scatter(cov, risk, color=color, marker=marker, s=size, label=label, zorder=5)
        
        dx = -2 if pol_id == "B6_RAEA" else (2 if cov > 90 else -4)
        dy = -0.08 if pol_id == "B5_M1_cov_pw" else 0.05
        ax.annotate(pol_id.split("_")[0], (cov, risk), textcoords="offset points", xytext=(dx*4, dy*60),
                    fontsize=8, fontweight="bold" if pol_id == "B6_RAEA" else "normal")

    ax.set_xlabel("Cobertura Operacional (%)")
    ax.set_ylabel("Riesgo Selectivo Penalizado (gamma=15, c_abst=0.35)")
    ax.set_title("Riesgo Ponderado vs Cobertura (Población: Phishing Web, N=118)")
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(loc="upper left", frameon=True)
    ax.set_xlim(70, 105)
    ax.set_ylim(0.2, 2.0)
    
    fig.savefig(FIG_DIR / "fig2_risk_vs_coverage.png")
    plt.close(fig)
    print("-> Generada: FIGURAS/fig2_risk_vs_coverage.png")


def plot_policy_comparison(df_res: pd.DataFrame):
    """Figura 3: Comparación multidimensional de políticas clave."""
    pw = df_res[df_res["population"] == "PHISHING_WEB_TEST"].copy()
    
    selected_pols = ["B1_M1", "B1_M1_bayes", "B3_entropy", "B5_M1_chow", "B6_RAEA"]
    pol_labels = ["M1 Fijo\n(0.50)", "M1 Bayes\n(tau*=0.06)", "Cascada\nEntropía", "M1 Chow\n(Selectiva B5)", "RAEA\n(Adaptativa B6)"]
    
    sub = pw.set_index("policy").loc[selected_pols]
    
    f1_sel = sub["sel_F1"].values
    f1_fo = sub["failopen_F1"].values
    risk = sub["risk_selective_penalized"].values
    cost = sub["mean_normalized_cost"].values
    
    x = np.arange(len(selected_pols))
    width = 0.2
    
    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    
    # Eje 1: Métricas de F1
    b1 = ax1.bar(x - width*1.5, f1_sel, width, label="F1 Selectivo", color="#2ca02c", alpha=0.85)
    b2 = ax1.bar(x - width*0.5, f1_fo, width, label="F1 Cobertura 100% (Fail-Open)", color="#1f77b4", alpha=0.85)
    ax1.set_ylabel("F1-Score")
    ax1.set_ylim(0.7, 1.05)
    
    # Eje 2: Riesgo y Coste
    ax2 = ax1.twinx()
    b3 = ax2.bar(x + width*0.5, risk, width, label="Riesgo Penalizado", color="#d62728", alpha=0.85)
    b4 = ax2.bar(x + width*1.5, cost, width, label="Coste Adquisición Normalizado", color="#ff7f0e", alpha=0.85)
    ax2.set_ylabel("Riesgo Penalizado / Coste Normalizado")
    ax2.set_ylim(0.0, 2.0)
    
    ax1.set_xticks(x)
    ax1.set_xticklabels(pol_labels)
    ax1.set_title("Comparación Multidimensional de Políticas (Phishing Web, N=118)")
    
    # Combinar leyendas
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", frameon=True, ncol=2)
    
    ax1.grid(True, linestyle="--", alpha=0.3, axis="y")
    
    fig.savefig(FIG_DIR / "fig3_policy_comparison.png")
    plt.close(fig)
    print("-> Generada: FIGURAS/fig3_policy_comparison.png")


def plot_ablations(df_abl: pd.DataFrame):
    """Figura 4: Análisis de ablación de componentes (A1-A6)."""
    pw_abl = df_abl[df_abl["population"] == "PHISHING_WEB_TEST"].copy()
    
    # Ordenar A1 a A6
    variants = ["A1", "A2", "A3", "A4", "A5", "A6"]
    var_labels = [
        "A1: Sin Disponibilidad\n(asume pi_m=1)",
        "A2: Sin Costes Asimétricos\n(gamma=1)",
        "A3: Sin Abstención\n(cobertura 100%)",
        "A4: Sin Beneficio Inf.\n(solo M0)",
        "A5: Sin Guarda Benigna\n(p_safe inactivo)",
        "A6: RAEA Completo\n(referencia)",
    ]
    
    sub = pw_abl.set_index("variant").loc[variants]
    
    f1_sel = sub["sel_F1"].values
    risk = sub["risk_selective_penalized"].values
    mods = sub["mean_modalities_requested_incl_url"].values
    
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(11, 4.2), sharey=False)
    
    y_pos = np.arange(len(variants))
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"]
    
    # Subplot 1: F1 Selectivo
    ax1.barh(y_pos, f1_sel, color="#2ca02c", alpha=0.8)
    ax1.axvline(sub.loc["A6", "sel_F1"], color="black", linestyle="--", alpha=0.7)
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels(var_labels, fontsize=8)
    ax1.set_xlabel("F1 Selectivo")
    ax1.set_title("F1 en Casos Decididos")
    ax1.set_xlim(0.7, 1.0)
    ax1.grid(True, linestyle="--", alpha=0.4, axis="x")
    
    # Subplot 2: Riesgo Selectivo Penalizado
    ax2.barh(y_pos, risk, color="#d62728", alpha=0.8)
    ax2.axvline(sub.loc["A6", "risk_selective_penalized"], color="black", linestyle="--", alpha=0.7)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels([])
    ax2.set_xlabel("Riesgo Penalizado")
    ax2.set_title("Pérdida Asimétrica Ponderada")
    ax2.grid(True, linestyle="--", alpha=0.4, axis="x")
    
    # Subplot 3: Modalidades Solicitadas
    ax3.barh(y_pos, mods, color="#1f77b4", alpha=0.8)
    ax3.axvline(sub.loc["A6", "mean_modalities_requested_incl_url"], color="black", linestyle="--", alpha=0.7)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels([])
    ax3.set_xlabel("Modalidades Solicitadas")
    ax3.set_title("Consumo de Modalidades (Media)")
    ax3.set_xlim(0.8, 2.3)
    ax3.grid(True, linestyle="--", alpha=0.4, axis="x")
    
    fig.suptitle("Estudio de Ablación de Componentes RAEA (Phishing Web, N=118)", y=1.02)
    fig.savefig(FIG_DIR / "fig4_ablations_analysis.png")
    plt.close(fig)
    print("-> Generada: FIGURAS/fig4_ablations_analysis.png")


def main():
    print("Generando figuras científicas...")
    df_res = pd.read_csv(DATA_DIR / "RESULTADOS_COMPARATIVOS.csv")
    df_abl = pd.read_csv(DATA_DIR / "ABLACIONES_VERIFICADAS.csv")
    
    plot_cost_coverage(df_res)
    plot_risk_coverage(df_res)
    plot_policy_comparison(df_res)
    plot_ablations(df_abl)
    print("Todas las figuras generadas con éxito en:", FIG_DIR)


if __name__ == "__main__":
    main()
