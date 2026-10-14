#!/usr/bin/env python3
"""
FASE VIII: SCRIPT MAESTRO DE REPRODUCIBILIDAD Y GENERACIÓN DE FIGURAS CIENTÍFICAS (300 DPI)
===========================================================================================
Regenera a partir de los artefactos verificados todas las tablas consolidadas y las 4 figuras
de calidad de publicación (300 DPI) para Revista Politécnica (Scopus):
  1. `fig1_external_generalization_paradox.png`
  2. `fig2_extension_latency_and_pareto.png`
  3. `fig3_calibration_and_prevalence_sensitivity.png`
  4. `fig4_visual_cdp_and_adversarial_robustness.png`
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
BASE_OUT = ROOT / "artifacts" / "validacion_scopus_fase2"
FIG_DIR = BASE_OUT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)


def generate_figures() -> list[str]:
    plt.rcParams.update({
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "figure.dpi": 300,
    })

    f2b = json.loads((BASE_OUT / "fase2_externa/02b_external_forensic_www_ablation.json").read_text(encoding="utf-8"))
    f4 = json.loads((BASE_OUT / "fase4_comparacion/04_comparacion_cientifica_results.json").read_text(encoding="utf-8"))
    f5 = json.loads((BASE_OUT / "fase5_cascada/05_cascada_ablaciones_results.json").read_text(encoding="utf-8"))
    f6 = json.loads((BASE_OUT / "fase6_visual_llm/06_visual_y_llm_results.json").read_text(encoding="utf-8"))
    f7 = json.loads((BASE_OUT / "fase7_estadistica/07_analisis_estadistico_results.json").read_text(encoding="utf-8"))

    saved_files: list[str] = []

    # =========================================================================
    # FIGURA 1: Generalización Externa y Paradoja de URL Completa vs Autoridad
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))

    models_f1 = [
        "CharNgram\nFull-URL",
        "Full-URL 36\n(HistGB)",
        "Full-URL 36\n(RF)",
        "CharNgram\nHost-Only",
        "PhishPe M0\n(11 Auth)",
        "HybridM0\n(Sin Tranco)",
        "HybridM0\n(Con Tranco)",
    ]
    auc_internal = [
        f4["baselines"]["Baseline2B_CharNgram_FullURL_LR"]["internal_n691"]["roc_auc"],
        f4["baselines"]["Baseline1B_FullURL36_HGB"]["internal_n691"]["roc_auc"],
        f4["baselines"]["Baseline1A_FullURL36_RF"]["internal_n691"]["roc_auc"],
        f4["baselines"]["Baseline2A_CharNgram_HostOnly_LR"]["internal_n691"]["roc_auc"],
        0.9522,
        0.9293,
        0.9963,
    ]
    auc_ext_raw = [
        f4["baselines"]["Baseline2B_CharNgram_FullURL_LR"]["external_n1054_raw"]["roc_auc"],
        f4["baselines"]["Baseline1B_FullURL36_HGB"]["external_n1054_raw"]["roc_auc"],
        f4["baselines"]["Baseline1A_FullURL36_RF"]["external_n1054_raw"]["roc_auc"],
        f4["baselines"]["Baseline2A_CharNgram_HostOnly_LR"]["external_n1054_raw"]["roc_auc"],
        f2b["n1054_m0_full_raw"]["roc_auc"],
        0.7710,
        0.8077,
    ]
    auc_ext_nowww = [
        f4["baselines"]["Baseline2B_CharNgram_FullURL_LR"]["external_n1054_strip_www"]["roc_auc"],
        f4["baselines"]["Baseline1B_FullURL36_HGB"]["external_n1054_strip_www"]["roc_auc"],
        f4["baselines"]["Baseline1A_FullURL36_RF"]["external_n1054_strip_www"]["roc_auc"],
        f4["baselines"]["Baseline2A_CharNgram_HostOnly_LR"]["external_n1054_strip_www"]["roc_auc"],
        f2b["n1054_m0_full_www_stripped"]["roc_auc"],
        0.7710,
        0.8077,
    ]

    x = np.arange(len(models_f1))
    w = 0.26
    axes[0].bar(x - w, auc_internal, width=w, label="Interno N=691 (host_unseen)", color="#2b5c8f")
    axes[0].bar(x, auc_ext_raw, width=w, label="Externo Crudo N=1,054", color="#d95f02")
    axes[0].bar(x + w, auc_ext_nowww, width=w, label="Externo strip_www N=1,054", color="#1b9e77")
    axes[0].axhline(0.50, color="red", linestyle="--", linewidth=1.0, label="Azar (AUC = 0.50)")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(models_f1, rotation=20, ha="right")
    axes[0].set_ylim(0.35, 1.05)
    axes[0].set_ylabel("ROC-AUC")
    axes[0].set_title("(a) Paradoja de Generalización: URL Completa vs. Autoridad")
    axes[0].legend(loc="lower right")
    axes[0].grid(axis="y", alpha=0.3)

    # Panel B: Progresión Multimodal en Cohorte Externa Viva Complete-Case (N_CC=104)
    mm_models = ["M0\n(Solo URL)", "M1\n(URL+Infra)", "M2\n(URL+Infra+DOM)", "Config C\n(HybridCascade)"]
    mm_auc_raw = [
        f2b["n104_cc_comparison"]["M0_CC_raw"]["roc_auc"],
        f2b["n104_cc_comparison"]["M1_CC_raw"]["roc_auc"],
        f2b["n104_cc_comparison"]["M2_CC_raw"]["roc_auc"],
        0.8380,
    ]
    mm_auc_nowww = [
        f2b["n104_cc_comparison"]["M0_CC_www_stripped"]["roc_auc"],
        f2b["n104_cc_comparison"]["M1_CC_www_stripped"]["roc_auc"],
        f2b["n104_cc_comparison"]["M2_CC_www_stripped"]["roc_auc"],
        0.9315,
    ]
    mm_pr_nowww = [
        f2b["n104_cc_comparison"]["M0_CC_www_stripped"]["pr_auc"],
        f2b["n104_cc_comparison"]["M1_CC_www_stripped"]["pr_auc"],
        f2b["n104_cc_comparison"]["M2_CC_www_stripped"]["pr_auc"],
        0.9460,
    ]
    x2 = np.arange(len(mm_models))
    axes[1].bar(x2 - w, mm_auc_raw, width=w, label="ROC-AUC Crudo (N_CC=104)", color="#d95f02")
    axes[1].bar(x2, mm_auc_nowww, width=w, label="ROC-AUC strip_www (N_CC=104)", color="#1b9e77")
    axes[1].bar(x2 + w, mm_pr_nowww, width=w, label="PR-AUC strip_www (N_CC=104)", color="#7570b3")
    axes[1].set_xticks(x2)
    axes[1].set_xticklabels(mm_models)
    axes[1].set_ylim(0.35, 1.05)
    axes[1].set_ylabel("Área Bajo la Curva (AUC)")
    axes[1].set_title("(b) Progresión Multimodal en Cohorte Externa Viva (N_CC = 104)")
    axes[1].legend(loc="lower right")
    axes[1].grid(axis="y", alpha=0.3)

    fig.tight_layout()
    p1 = FIG_DIR / "fig1_external_generalization_paradox.png"
    fig.savefig(p1, dpi=300)
    plt.close(fig)
    saved_files.append(str(p1))

    # =========================================================================
    # FIGURA 2: Latencia Real de la Extensión vs Frontera de Pareto de la Cascada
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))

    configs_lat = ["Config A\n(Caché Cálida)", "Config C\n(Interno N=691)", "Config C\n(Externo N=104)", "Config A\n(Caché Fría)", "Config B\n(Cascada API)"]
    p50s = [17.11, 51.51, 68.33, 994.45, 1205.51]
    p95s = [38.35, 3682.69, 4449.55, 3620.06, 4464.59]
    x_l = np.arange(len(configs_lat))
    axes[0].bar(x_l - 0.18, p50s, width=0.35, label="Mediana P50 (ms)", color="#2b5c8f")
    axes[0].bar(x_l + 0.18, p95s, width=0.35, label="Percentil P95 (ms)", color="#e7298a")
    axes[0].axhline(6000.0, color="red", linestyle="--", linewidth=1.2, label="Timeout Extensión (6,000 ms)")
    axes[0].set_yscale("log")
    axes[0].set_xticks(x_l)
    axes[0].set_xticklabels(configs_lat, rotation=15, ha="right")
    axes[0].set_ylabel("Latencia End-to-End (ms, escala log)")
    axes[0].set_title("(a) Latencia Operativa Medida en Servidor Real (Loopback HTTP)")
    axes[0].legend(loc="upper left")
    axes[0].grid(axis="y", alpha=0.3)

    # Panel B: Frontera de Pareto F1 vs Costo Medio de Etapas en N=691
    pts = [
        ("M0 Solo", 1.00, 0.8658, "#888888"),
        ("M1 Monolítico", 2.00, 0.9188, "#377eb8"),
        ("M4 Cascada Estándar", 1.787, 0.9248, "#ff7f00"),
        ("Cascada Conservadora\n(M1 Oblig. Benigno)", 2.151, 0.9341, "#4daf4a"),
        ("M5 Fail-Closed\n(Cautelar)", 1.787, 0.9387, "#984ea3"),
        ("M2 Monolítico", 3.00, 0.9315, "#e41a1c"),
        ("Config C (Extensión+\nCascada)", 1.483, 0.9178, "#a65628"),
    ]
    for label_p, stages_m, f1_v, col in pts:
        axes[1].scatter(stages_m, f1_v, s=90, color=col, zorder=4)
        axes[1].annotate(label_p, (stages_m, f1_v), xytext=(6, -4), textcoords="offset points", fontsize=8.5)
    axes[1].set_xlim(0.85, 3.35)
    axes[1].set_ylim(0.855, 0.950)
    axes[1].set_xlabel("Costo Medio de Evaluación (Etapas / Modalidades por URL)")
    axes[1].set_ylabel("F1-Score en Cohorte Completa (N = 691)")
    axes[1].set_title("(b) Frontera de Pareto: Costo de Modalidades vs. F1-Score")
    axes[1].grid(True, alpha=0.3)

    fig.tight_layout()
    p2 = FIG_DIR / "fig2_extension_latency_and_pareto.png"
    fig.savefig(p2, dpi=300)
    plt.close(fig)
    saved_files.append(str(p2))

    # =========================================================================
    # FIGURA 3: Diagrama de Confiabilidad (Calibración) y Sensibilidad a Prevalencia
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))

    axes[0].plot([0, 1], [0, 1], "k--", linewidth=1.0, label="Calibración Perfecta")
    for m_k, label_c, col in (
        ("Internal_M0", "M0 (Brier=0.060, ECE=0.066)", "#d95f02"),
        ("Internal_M2", "M2 (Brier=0.040, ECE=0.068)", "#2b5c8f"),
        ("Internal_M4", "M4 Calibrada (Brier=0.031, ECE=0.021)", "#1b9e77"),
        ("Internal_HybridM0_ConfigA", "HybridM0 Extensión (Brier=0.044)", "#e7298a"),
    ):
        bins_data = f7["calibration_and_reliability_analysis"][m_k]["reliability_bins"]
        mp = [b["mean_predicted_prob"] for b in bins_data if b["count"] > 0]
        ep = [b["empirical_positive_rate"] for b in bins_data if b["count"] > 0]
        axes[0].plot(mp, ep, marker="o", linewidth=1.8, label=label_c, color=col)
    axes[0].set_xlabel("Probabilidad Media Predicha")
    axes[0].set_ylabel("Fracción Empírica de Phishing")
    axes[0].set_title("(a) Diagrama de Confiabilidad (10 Bins, N = 691)")
    axes[0].legend(loc="upper left")
    axes[0].grid(True, alpha=0.3)

    # Panel B: Sensibilidad a la Prevalencia Operativa
    for m_k, label_p, col in (
        ("Internal_M0", "M0 (FPR=3.20%)", "#d95f02"),
        ("Internal_M2", "M2 (FPR=0.40%)", "#2b5c8f"),
        ("Internal_M4", "M4 Cascada (FPR=0.20%)", "#1b9e77"),
        ("Internal_M5_FailClosed", "M5 Fail-Closed (FPR=1.60%)", "#7570b3"),
        ("External_HybridM0_WithTranco_N1054", "HybridM0 Externo (FPR=1.32%)", "#e7298a"),
    ):
        p_rows = f7["prevalence_sensitivity_analysis"][m_k]
        pis = [r["prevalence_pct"] for r in p_rows]
        ppvs = [r["projected_precision_ppv"] for r in p_rows]
        axes[1].plot(pis, ppvs, marker="s", linewidth=1.8, label=label_p, color=col)
    axes[1].set_xscale("log")
    axes[1].set_xlabel("Prevalencia Operativa de Phishing (%, escala log)")
    axes[1].set_ylabel("Precisión Proyectada (PPV)")
    axes[1].set_title("(b) Sensibilidad de la Precisión (PPV) a la Prevalencia")
    axes[1].legend(loc="lower right")
    axes[1].grid(True, alpha=0.3)

    fig.tight_layout()
    p3 = FIG_DIR / "fig3_calibration_and_prevalence_sensitivity.png"
    fig.savefig(p3, dpi=300)
    plt.close(fig)
    saved_files.append(str(p3))

    # =========================================================================
    # FIGURA 4: Ablación Visual Chrome CDP (N=83) y Robustez Adversarial (6 Familias)
    # =========================================================================
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))

    v_models = ["Visual Only\n(32 vars)", "M0\n(URL)", "M1\n(URL+Infra)", "M2\n(+DOM)", "M3 Global\n(82 vars)", "M3 CDP\n(N=312 train)"]
    v_f1 = [
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["Visual_Only_32feat"]["f1"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M0"]["f1"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M1"]["f1"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M2"]["f1"],
        0.9231,
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M3_authentic_cdp"]["f1"],
    ]
    v_auc = [
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["Visual_Only_32feat"]["roc_auc"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M0"]["roc_auc"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M1"]["roc_auc"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M2"]["roc_auc"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M3_global"]["roc_auc"],
        f6["visual_component_audit"]["availability_bias_analysis"]["models_on_n83_with_cdp"]["M3_authentic_cdp"]["roc_auc"],
    ]
    xv = np.arange(len(v_models))
    axes[0].bar(xv - 0.18, v_f1, width=0.35, label="F1-Score (N=83 CDP)", color="#2b5c8f")
    axes[0].bar(xv + 0.18, v_auc, width=0.35, label="ROC-AUC (N=83 CDP)", color="#1b9e77")
    axes[0].axhline(0.50, color="red", linestyle="--", linewidth=1.0, label="Azar (0.50)")
    axes[0].set_xticks(xv)
    axes[0].set_xticklabels(v_models, rotation=15, ha="right")
    axes[0].set_ylim(0.30, 1.05)
    axes[0].set_ylabel("Métrica en Cohorte CDP Auténtica (N = 83)")
    axes[0].set_title("(a) Evaluación Controlada Visual Chrome CDP (N = 83)")
    axes[0].legend(loc="lower right")
    axes[0].grid(axis="y", alpha=0.3)

    # Panel B: Robustez Adversarial por Familia de Ataque (ASR)
    fams = ["Homoglyph\nSubst.", "Subdomain\nPadding", "Hyphen\nInsertion", "URL\nShortener", "Query\nNoise", "Form\nObfusc."]
    asr_m0 = [23.04, 15.18, 17.80, 100.00, 17.28, 17.28]
    asr_m2 = [13.61, 11.52, 13.09, 100.00, 12.04, 14.66]
    asr_m5_silent = [10.47, 7.85, 8.90, 99.48, 7.85, 7.85]
    xa = np.arange(len(fams))
    wa = 0.26
    axes[1].bar(xa - wa, asr_m0, width=wa, label="M0 ASR (%)", color="#d95f02")
    axes[1].bar(xa, asr_m2, width=wa, label="M2 ASR (%)", color="#2b5c8f")
    axes[1].bar(xa + wa, asr_m5_silent, width=wa, label="M5 Evasión Silenciosa (%)", color="#1b9e77")
    axes[1].set_xticks(xa)
    axes[1].set_xticklabels(fams, rotation=20, ha="right")
    axes[1].set_ylabel("Attack Success Rate — ASR (%)")
    axes[1].set_title("(b) Robustez Adversarial ante 6 Familias de Evasión (N = 191)")
    axes[1].legend(loc="upper left")
    axes[1].grid(axis="y", alpha=0.3)

    fig.tight_layout()
    p4 = FIG_DIR / "fig4_visual_cdp_and_adversarial_robustness.png"
    fig.savefig(p4, dpi=300)
    plt.close(fig)
    saved_files.append(str(p4))

    return saved_files


if __name__ == "__main__":
    files = generate_figures()
    print("Figuras generadas exitosamente:", files)
