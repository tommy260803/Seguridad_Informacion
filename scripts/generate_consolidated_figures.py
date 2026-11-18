"""
Generador de figuras cientificas consolidadas para el articulo.
Genera las 4 figuras obligatorias en el directorio FIGURAS/.
"""
from __future__ import annotations

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "FIGURAS"
FIG_DIR.mkdir(parents=True, exist_ok=True)

plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

# Cargar tablas de resultados
df_retro = pd.read_csv(ROOT / "autonomous_reproduction_suite" / "output" / "RESULTADOS_REPRODUCIDOS.csv")
df_retro_pols = df_retro[df_retro["population"] == "PHISHING_WEB_TEST"].copy()

df_indep = pd.read_csv(ROOT / "artifacts" / "raea_independent_n240" / "RESULTADOS_INDEPENDIENTES_N240.csv")

df_ab_retro = pd.read_csv(ROOT / "autonomous_reproduction_suite" / "output" / "ABLACIONES_REPRODUCIDAS.csv")
df_ab_indep = pd.read_csv(ROOT / "artifacts" / "raea_independent_n240" / "ABLACIONES_INDEPENDIENTES_N240.csv")

# 1. FIG 1: Trade-off Coste vs Cobertura (Panel dual: N=118 y N=240)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), sharey=True)

# Panel N=118
ax1.scatter(df_retro_pols["mean_normalized_cost"], df_retro_pols["coverage"], s=120, color="navy", zorder=3)
for _, r in df_retro_pols.iterrows():
    ax1.annotate(r["policy"], (r["mean_normalized_cost"] + 0.01, r["coverage"] - 0.015), fontsize=8.5)
ax1.set_xlabel("Coste Normalizado de Adquisicion")
ax1.set_ylabel("Cobertura Selectiva")
ax1.set_title("A. Cohorte Retrospectiva (N=118)")

# Panel N=240
ax2.scatter(df_indep["mean_normalized_cost"], df_indep["coverage"], s=120, color="teal", zorder=3)
for _, r in df_indep.iterrows():
    ax2.annotate(r["policy"], (r["mean_normalized_cost"] + 0.015, r["coverage"] - 0.02), fontsize=8.5)
ax2.set_xlabel("Coste Normalizado de Adquisicion")
ax2.set_title("B. Cohorte Externa Independiente (N=240)")

fig.suptitle("Compromiso Coste-Cobertura entre Politicas Basales y RAEA", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(FIG_DIR / "fig1_tradeoff_cost_coverage.png", dpi=300)
plt.close(fig)

# 2. FIG 2: Riesgo Penalizado vs Cobertura Selectiva
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

ax1.scatter(df_retro_pols["coverage"], df_retro_pols["risk_selective_penalized"], s=120, color="crimson", zorder=3)
for _, r in df_retro_pols.iterrows():
    ax1.annotate(r["policy"], (r["coverage"] + 0.005, r["risk_selective_penalized"] + 0.05), fontsize=8.5)
ax1.set_xlabel("Cobertura Selectiva")
ax1.set_ylabel("Riesgo Penalizado Esperado (gamma=15.0)")
ax1.set_title("A. Cohorte Retrospectiva (N=118)")

ax2.scatter(df_indep["coverage"], df_indep["penalized_risk"], s=120, color="darkred", zorder=3)
for _, r in df_indep.iterrows():
    ax2.annotate(r["policy"], (r["coverage"] + 0.01, r["penalized_risk"] + 0.08), fontsize=8.5)
ax2.set_xlabel("Cobertura Selectiva")
ax2.set_ylabel("Riesgo Penalizado Esperado (gamma=15.0)")
ax2.set_title("B. Cohorte Externa Independiente (N=240)")

fig.suptitle("Riesgo Penalizado vs Cobertura Selectiva", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(FIG_DIR / "fig2_risk_vs_coverage.png", dpi=300)
plt.close(fig)

# 3. FIG 3: Comparativa F1 y Regímenes de Abstención (Selectivo, Fail-Open, Fail-Closed)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

pols_retro = ["B0_M0", "B1_M1", "B5_M1_chow", "B6_RAEA"]
sub_r = df_retro_pols[df_retro_pols["policy"].isin(pols_retro)].copy()
x1 = np.arange(len(pols_retro))
w = 0.25

ax1.bar(x1 - w, sub_r["sel_F1"], width=w, label="F1 Selectivo", color="#1f77b4")
ax1.bar(x1, sub_r["failopen_F1"], width=w, label="F1 Fail-Open (0)", color="#2ca02c")
ax1.bar(x1 + w, sub_r["failclosed_F1"], width=w, label="F1 Fail-Closed (1)", color="#d62728")
ax1.set_xticks(x1)
ax1.set_xticklabels(pols_retro, rotation=15)
ax1.set_ylabel("F1-Score")
ax1.set_title("A. Regímenes de Abstención en Retrospectivo (N=118)")
ax1.legend(loc="lower right")

sub_i = df_indep[df_indep["policy"].isin(pols_retro)].copy()
x2 = np.arange(len(pols_retro))

ax2.bar(x2 - w, sub_i["sel_F1"], width=w, label="F1 Selectivo", color="#1f77b4")
ax2.bar(x2, sub_i["failopen_F1"], width=w, label="F1 Fail-Open (0)", color="#2ca02c")
ax2.bar(x2 + w, sub_i["failclosed_F1"], width=w, label="F1 Fail-Closed (1)", color="#d62728")
ax2.set_xticks(x2)
ax2.set_xticklabels(pols_retro, rotation=15)
ax2.set_ylabel("F1-Score")
ax2.set_title("B. Regímenes de Abstención en Independiente (N=240)")
ax2.legend(loc="lower right")

fig.suptitle("Efecto de las Políticas de Abstención sobre el F1-Score", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(FIG_DIR / "fig3_policy_comparison_n118_n240.png", dpi=300)
plt.close(fig)

# 4. FIG 4: Analisis de Ablaciones A1-A6 (Impacto en Coste y Riesgo)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

vars_names = ["A1", "A2", "A3", "A4", "A5", "A6"]
ax1.barh(vars_names, df_ab_retro["mean_normalized_cost"], color="steelblue")
ax1.set_xlabel("Coste Normalizado")
ax1.set_title("A. Coste por Ablación (Retrospectivo N=118)")

ax2.barh(vars_names, df_ab_indep["normalized_cost"], color="darkorange")
ax2.set_xlabel("Coste Normalizado")
ax2.set_title("B. Coste por Ablación (Independiente N=240)")

fig.suptitle("Análisis de Componentes RAEA (Ablaciones A1-A6)", fontsize=13, fontweight="bold")
fig.tight_layout()
fig.savefig(FIG_DIR / "fig4_ablations_analysis.png", dpi=300)
plt.close(fig)

print("4 figuras consolidadas generadas en FIGURAS/:")
for f in FIG_DIR.glob("*.png"):
    print(f"  + {f.name} ({f.stat().st_size} bytes)")
