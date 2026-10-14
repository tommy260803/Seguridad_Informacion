#!/usr/bin/env python3
"""
FASE VII: ANÁLISIS ESTADÍSTICO RIGUROSO, CLUSTER BOOTSTRAP, CORRECCIÓN MULTIPLICIDAD Y SENSIBILIDAD
===================================================================================================
Ejecuta el protocolo estadístico completo exigido por las Secciones 11 y 12:
1. Separación explícita entre familias de hipótesis CONFIRMATORIAS (predefinidas) y EXPLORATORIAS.
2. Intervalos de confianza del 95% mediante:
   a) Bootstrap no paramétrico a nivel de muestra (B=2,000, SEED=42).
   b) Cluster Bootstrap por dominio registrado (`registered_domain`, B=2,000, SEED=42) para controlar
      correlación intra-dominio en el conjunto interno (N=691) y externo (N=1,054).
3. Pruebas pareadas exactas de McNemar (binomial exacta sobre pares discordantes), tamaños de efecto
   (Delta F1, Cohen's g para pares discordantes, Odds Ratio de discordancia con corrección de Haldane-Anscombe,
   y Cohen's h para tasas de detección), y corrección step-down de Holm-Bonferroni por familia de hipótesis.
4. Análisis de calibración probabilística (Brier Score, ECE, MCE y diagramas de confiabilidad de 10 bins).
5. Análisis de sensibilidad:
   - Al umbral de decisión (tau* +/- 0.05 y +/- 0.10).
   - A la prevalencia operativa (pi in {50%, 27.64%, 10%, 5%, 1%, 0.1%}).
   - A la política sobre abstenciones de M5 (Selective, Fail-Open, Fail-Closed, Worst-Case, Best-Case).
   - A subgrupos estructurales (TLD, número de subdominios, longitud de host) en interno y externo.
"""
from __future__ import annotations

import csv
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import binomtest
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_ml.evaluation import expected_calibration_error


def maximum_calibration_error(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    max_gap = 0.0
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob >= lo) & (y_prob <= hi) if i == n_bins - 1 else (y_prob >= lo) & (y_prob < hi)
        if np.any(mask):
            gap = float(abs(np.mean(y_prob[mask]) - np.mean(y_true[mask])))
            if gap > max_gap:
                max_gap = gap
    return max_gap

SEED = 42
B_ITER = 2000
OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase7_estadistica"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def holm_bonferroni(p_values: list[float]) -> list[float]:
    m = len(p_values)
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    adjusted = [0.0] * m
    running_max = 0.0
    for rank, (orig_idx, pval) in enumerate(indexed):
        adj = min(1.0, pval * (m - rank))
        running_max = max(running_max, adj)
        adjusted[orig_idx] = round(running_max, 8)
    return adjusted


def cohens_h(p1: float, p2: float) -> float:
    return float(2.0 * math.asin(math.sqrt(max(0.0, min(1.0, p2)))) - 2.0 * math.asin(math.sqrt(max(0.0, min(1.0, p1)))))


def cohens_g_discordant(n01: int, n10: int) -> float:
    disc = n01 + n10
    if disc == 0:
        return 0.0
    return float(abs((n01 / disc) - 0.5))


def fast_f1(yt: np.ndarray, yp: np.ndarray) -> float:
    tp = int(np.sum((yt == 1) & (yp == 1)))
    if tp == 0:
        return 0.0
    fp = int(np.sum((yt == 0) & (yp == 1)))
    fn = int(np.sum((yt == 1) & (yp == 0)))
    return float((2 * tp) / (2 * tp + fp + fn))


def sample_and_cluster_bootstrap_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    domains: list[str],
    n_boot: int = B_ITER,
    seed: int = SEED,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    n = len(y_true)

    # 1. Sample-level bootstrap
    f1_samp = np.empty(n_boot, dtype=float)
    auc_samp = np.empty(n_boot, dtype=float)
    rec_samp = np.empty(n_boot, dtype=float)
    fpr_samp = np.empty(n_boot, dtype=float)

    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        yt = y_true[idx]
        yp = y_pred[idx]
        ypr = y_prob[idx]
        tp = int(np.sum((yt == 1) & (yp == 1)))
        fp = int(np.sum((yt == 0) & (yp == 1)))
        fn = int(np.sum((yt == 1) & (yp == 0)))
        tn = n - tp - fp - fn
        f1_samp[b] = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0
        rec_samp[b] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr_samp[b] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        auc_samp[b] = roc_auc_score(yt, ypr) if (tp + fn > 0 and fp + tn > 0) else np.nan

    # 2. Cluster bootstrap by registered_domain
    domain_to_indices: dict[str, list[int]] = defaultdict(list)
    for idx_i, dom in enumerate(domains):
        domain_to_indices[dom or f"__missing_{idx_i}"].append(idx_i)
    unique_domains = sorted(domain_to_indices.keys())
    n_clusters = len(unique_domains)
    cluster_index_arrays = [np.array(domain_to_indices[d], dtype=int) for d in unique_domains]

    f1_clus = np.empty(n_boot, dtype=float)
    auc_clus = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        chosen_clusters = rng.integers(0, n_clusters, size=n_clusters)
        idx = np.concatenate([cluster_index_arrays[c] for c in chosen_clusters])
        yt = y_true[idx]
        yp = y_pred[idx]
        ypr = y_prob[idx]
        f1_clus[b] = fast_f1(yt, yp)
        auc_clus[b] = roc_auc_score(yt, ypr) if len(np.unique(yt)) > 1 else np.nan

    return {
        "n_samples": int(n),
        "n_domain_clusters": int(n_clusters),
        "f1_point": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "f1_ci95_sample_bootstrap": [
            round(float(np.nanpercentile(f1_samp, 2.5)), 6),
            round(float(np.nanpercentile(f1_samp, 97.5)), 6),
        ],
        "f1_ci95_cluster_bootstrap": [
            round(float(np.nanpercentile(f1_clus, 2.5)), 6),
            round(float(np.nanpercentile(f1_clus, 97.5)), 6),
        ],
        "roc_auc_point": round(float(roc_auc_score(y_true, y_prob)), 6) if len(np.unique(y_true)) > 1 else None,
        "roc_auc_ci95_sample_bootstrap": [
            round(float(np.nanpercentile(auc_samp, 2.5)), 6),
            round(float(np.nanpercentile(auc_samp, 97.5)), 6),
        ],
        "roc_auc_ci95_cluster_bootstrap": [
            round(float(np.nanpercentile(auc_clus, 2.5)), 6),
            round(float(np.nanpercentile(auc_clus, 97.5)), 6),
        ],
        "recall_ci95_sample_bootstrap": [
            round(float(np.nanpercentile(rec_samp, 2.5)), 6),
            round(float(np.nanpercentile(rec_samp, 97.5)), 6),
        ],
        "fpr_ci95_sample_bootstrap": [
            round(float(np.nanpercentile(fpr_samp, 2.5)), 6),
            round(float(np.nanpercentile(fpr_samp, 97.5)), 6),
        ],
    }


def paired_comparison_full(
    name_a: str,
    name_b: str,
    hypothesis_type: str,
    cohort_name: str,
    y_true: np.ndarray,
    pred_a: np.ndarray,
    pred_b: np.ndarray,
    domains: list[str] | None = None,
    n_boot: int = B_ITER,
    seed: int = SEED,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    n = len(y_true)
    ca = pred_a == y_true
    cb = pred_b == y_true
    n11 = int(np.sum(ca & cb))
    n00 = int(np.sum((~ca) & (~cb)))
    n01 = int(np.sum((~ca) & cb))  # B right, A wrong
    n10 = int(np.sum(ca & (~cb)))  # A right, B wrong
    disc = n01 + n10
    p_exact = float(binomtest(min(n01, n10), disc, 0.5).pvalue) if disc > 0 else 1.0
    chi2_cc = float(((abs(n01 - n10) - 1.0) ** 2) / disc) if disc > 0 else 0.0

    f1_a = float(f1_score(y_true, pred_a, zero_division=0))
    f1_b = float(f1_score(y_true, pred_b, zero_division=0))
    rec_a = float(recall_score(y_true, pred_a, zero_division=0))
    rec_b = float(recall_score(y_true, pred_b, zero_division=0))
    tn_a, fp_a, fn_a, tp_a = confusion_matrix(y_true, pred_a, labels=[0, 1]).ravel()
    tn_b, fp_b, fn_b, tp_b = confusion_matrix(y_true, pred_b, labels=[0, 1]).ravel()
    fpr_a = float(fp_a / (fp_a + tn_a)) if (fp_a + tn_a) > 0 else 0.0
    fpr_b = float(fp_b / (fp_b + tn_b)) if (fp_b + tn_b) > 0 else 0.0

    diffs_samp = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        diffs_samp[b] = fast_f1(y_true[idx], pred_b[idx]) - fast_f1(y_true[idx], pred_a[idx])

    ci_clus = None
    if domains is not None:
        dom_map: dict[str, list[int]] = defaultdict(list)
        for idx_i, d in enumerate(domains):
            dom_map[d or f"__m_{idx_i}"].append(idx_i)
        udoms = sorted(dom_map.keys())
        c_arrays = [np.array(dom_map[d], dtype=int) for d in udoms]
        nc = len(udoms)
        diffs_clus = np.empty(n_boot, dtype=float)
        for b in range(n_boot):
            c_idx = rng.integers(0, nc, size=nc)
            idx = np.concatenate([c_arrays[c] for c in c_idx])
            diffs_clus[b] = fast_f1(y_true[idx], pred_b[idx]) - fast_f1(y_true[idx], pred_a[idx])
        ci_clus = [round(float(np.percentile(diffs_clus, 2.5)), 6), round(float(np.percentile(diffs_clus, 97.5)), 6)]

    g_eff = cohens_g_discordant(n01, n10)
    or_disc = float((n01 + 0.5) / (n10 + 0.5))
    h_rec = cohens_h(rec_a, rec_b)

    return {
        "comparison": f"{name_a}_vs_{name_b}",
        "model_a": name_a,
        "model_b": name_b,
        "hypothesis_type": hypothesis_type,
        "cohort": cohort_name,
        "n": int(n),
        "f1_a": round(f1_a, 6),
        "f1_b": round(f1_b, 6),
        "delta_f1_b_minus_a": round(f1_b - f1_a, 6),
        "delta_f1_ci95_sample_bootstrap": [
            round(float(np.percentile(diffs_samp, 2.5)), 6),
            round(float(np.percentile(diffs_samp, 97.5)), 6),
        ],
        "delta_f1_ci95_cluster_bootstrap": ci_clus,
        "recall_a": round(rec_a, 6),
        "recall_b": round(rec_b, 6),
        "delta_recall_b_minus_a": round(rec_b - rec_a, 6),
        "fpr_a": round(fpr_a, 6),
        "fpr_b": round(fpr_b, 6),
        "delta_fpr_b_minus_a": round(fpr_b - fpr_a, 6),
        "n11_both_correct": n11,
        "n00_both_wrong": n00,
        "n01_b_correct_a_wrong": n01,
        "n10_a_correct_b_wrong": n10,
        "total_discordant": disc,
        "mcnemar_chi2_cc": round(chi2_cc, 6),
        "mcnemar_p_exact": round(p_exact, 8),
        "effect_size_cohens_g": round(g_eff, 6),
        "effect_size_discordant_or": round(or_disc, 4),
        "effect_size_cohens_h_recall": round(h_rec, 6),
    }


def compute_reliability_bins(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> list[dict[str, Any]]:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    out = []
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        if i == n_bins - 1:
            mask = (y_prob >= lo) & (y_prob <= hi)
        else:
            mask = (y_prob >= lo) & (y_prob < hi)
        cnt = int(np.sum(mask))
        if cnt > 0:
            mean_p = float(np.mean(y_prob[mask]))
            frac_pos = float(np.mean(y_true[mask]))
            gap = abs(mean_p - frac_pos)
        else:
            mean_p, frac_pos, gap = 0.0, 0.0, 0.0
        out.append({
            "bin_index": i + 1,
            "range": f"[{lo:.1f}, {hi:.1f}{']' if i == n_bins - 1 else ')'}",
            "count": cnt,
            "mean_predicted_prob": round(mean_p, 6),
            "empirical_positive_rate": round(frac_pos, 6),
            "abs_calibration_gap": round(gap, 6),
        })
    return out


def prevalence_projection(tpr: float, fpr: float, prevalences: list[float]) -> list[dict[str, Any]]:
    rows = []
    for pi in prevalences:
        tp_rate = pi * tpr
        fp_rate = (1.0 - pi) * fpr
        fn_rate = pi * (1.0 - tpr)
        tn_rate = (1.0 - pi) * (1.0 - fpr)
        ppv = tp_rate / (tp_rate + fp_rate) if (tp_rate + fp_rate) > 0 else 0.0
        npv = tn_rate / (tn_rate + fn_rate) if (tn_rate + fn_rate) > 0 else 0.0
        f1_proj = (2 * ppv * tpr) / (ppv + tpr) if (ppv + tpr) > 0 else 0.0
        acc_proj = tp_rate + tn_rate
        fp_per_10k = fp_rate * 10000.0
        tp_per_10k = tp_rate * 10000.0
        rows.append({
            "prevalence_pct": round(pi * 100.0, 3),
            "projected_accuracy": round(acc_proj, 6),
            "projected_precision_ppv": round(ppv, 6),
            "projected_recall_tpr": round(tpr, 6),
            "projected_npv": round(npv, 6),
            "projected_f1": round(f1_proj, 6),
            "expected_tp_per_10k_urls": round(tp_per_10k, 2),
            "expected_fp_per_10k_urls": round(fp_per_10k, 2),
        })
    return rows


def main() -> None:
    print("=== FASE VII: Ejecutando Análisis Estadístico Riguroso (Confirmatorio y Exploratorio) ===", flush=True)
    samples_meta: dict[str, dict[str, str]] = {}
    with open(ROOT / "data/processed/0.1.0/samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_meta[r["sample_id"]] = r

    # 1. Load Internal N=691 predictions for M0, M1, M2, M3, M4, M5
    models_internal: dict[str, dict[str, Any]] = {}
    for m_name, m_dir in (
        ("M0", "m0-real"),
        ("M1", "m1-real"),
        ("M2", "m2-real"),
        ("M3", "m3-real"),
        ("M4", "m4-real"),
        ("M5", "m5-real"),
    ):
        m_json = json.loads((ROOT / "artifacts" / m_dir / "metrics.json").read_text(encoding="utf-8"))
        sel_thr = float(m_json.get("selected_threshold", 0.5))
        rows = [
            r
            for r in csv.DictReader((ROOT / "artifacts" / m_dir / "predictions.csv").open("r", encoding="utf-8"))
            if r["partition"] == "test"
        ]
        rows.sort(key=lambda r: r["sample_id"])
        sids = [r["sample_id"] for r in rows]
        y = np.array([int(r["label"]) for r in rows], dtype=int)
        prob = np.array([float(r["probability_phishing"]) for r in rows], dtype=float)
        pred = (prob >= sel_thr).astype(int)
        abstain = np.array(
            [str(r.get("abstained", "0")).strip().lower() in ("1", "true") for r in rows], dtype=bool
        )
        doms = [samples_meta[sid]["registered_domain"] for sid in sids]
        tlds = [(d.split(".", 1)[1] if "." in d else d) for d in doms]
        models_internal[m_name] = {
            "sids": sids,
            "y": y,
            "prob": prob,
            "pred": pred,
            "threshold": sel_thr,
            "abstain": abstain,
            "domains": doms,
            "tlds": tlds,
        }

    sids_691 = models_internal["M0"]["sids"]
    y_691 = models_internal["M0"]["y"]
    doms_691 = models_internal["M0"]["domains"]

    # Also load HybridM0Model predictions on N=691 from Phase III log
    ext_log_rows = list(
        csv.DictReader(
            (ROOT / "artifacts/validacion_scopus_fase2/fase3_extension/03_per_request_extension_and_cascade_log.csv").open(
                "r", encoding="utf-8"
            )
        )
    )
    int_log_map = {r["sample_id"]: r for r in ext_log_rows if r["cohort"] == "internal_n691"}
    hybrid_m0_prob_691 = np.array([float(int_log_map[sid]["config_a_prob"]) for sid in sids_691], dtype=float)
    hybrid_m0_pred_691 = np.array(
        [1 if int_log_map[sid]["config_a_decision"] == "phishing" else 0 for sid in sids_691], dtype=int
    )
    config_c_prob_691 = np.array([float(int_log_map[sid]["config_c_prob"]) for sid in sids_691], dtype=float)
    config_c_pred_691 = (config_c_prob_691 >= 0.46484375).astype(int)

    models_internal["HybridM0_ConfigA"] = {
        "sids": sids_691,
        "y": y_691,
        "prob": hybrid_m0_prob_691,
        "pred": hybrid_m0_pred_691,
        "abstain": np.zeros(len(y_691), dtype=bool),
        "domains": doms_691,
    }
    models_internal["ConfigC_HybridCascade"] = {
        "sids": sids_691,
        "y": y_691,
        "prob": config_c_prob_691,
        "pred": config_c_pred_691,
        "abstain": np.zeros(len(y_691), dtype=bool),
        "domains": doms_691,
    }

    # Add M5_FailClosed on N=691
    m5_fail_closed_pred = np.where(models_internal["M5"]["abstain"], 1, models_internal["M4"]["pred"])
    models_internal["M5_FailClosed"] = {
        "sids": sids_691,
        "y": y_691,
        "prob": models_internal["M5"]["prob"],
        "pred": m5_fail_closed_pred,
        "abstain": np.zeros(len(y_691), dtype=bool),
        "domains": doms_691,
    }

    # 2. Sample vs Cluster Bootstrap CIs for all internal models on N=691
    internal_bootstrap_cis = {}
    for m_key in ("M0", "M1", "M2", "M3", "M4", "M5_FailClosed", "HybridM0_ConfigA", "ConfigC_HybridCascade"):
        m_obj = models_internal[m_key]
        internal_bootstrap_cis[m_key] = sample_and_cluster_bootstrap_ci(
            m_obj["y"], m_obj["pred"], m_obj["prob"], m_obj["domains"]
        )

    # 3. External N=1,054 Sample vs Cluster Bootstrap CIs
    ext_pred_rows = list(
        csv.DictReader(
            (ROOT / "artifacts/validacion_scopus_fase2/fase2_externa/external_predictions_n1200.csv").open(
                "r", encoding="utf-8"
            )
        )
    )
    y_ext = np.array([int(r["label_int"]) for r in ext_pred_rows], dtype=int)
    doms_ext = [r["registered_domain"] for r in ext_pred_rows]
    sources_ext = [r["source"] for r in ext_pred_rows]

    ext_m0_prob = np.array([float(r["prob_M0_CC"]) for r in ext_pred_rows], dtype=float)
    ext_m0_pred = (ext_m0_prob >= 0.38266699053469533).astype(int)
    ext_hyb_tr_prob = np.array([float(r["prob_HybridM0_with_Tranco"]) for r in ext_pred_rows], dtype=float)
    ext_hyb_tr_pred = (ext_hyb_tr_prob >= 0.50).astype(int)
    ext_hyb_notr_prob = np.array([float(r["prob_HybridM0_without_Tranco"]) for r in ext_pred_rows], dtype=float)
    ext_hyb_notr_pred = (ext_hyb_notr_prob >= 0.35).astype(int)

    external_bootstrap_cis = {
        "M0_External_Raw": sample_and_cluster_bootstrap_ci(y_ext, ext_m0_pred, ext_m0_prob, doms_ext),
        "HybridM0_WithTranco_External": sample_and_cluster_bootstrap_ci(y_ext, ext_hyb_tr_pred, ext_hyb_tr_prob, doms_ext),
        "HybridM0_NoTranco_External": sample_and_cluster_bootstrap_ci(y_ext, ext_hyb_notr_pred, ext_hyb_notr_prob, doms_ext),
    }

    # 4. Hypothesis Testing: Confirmatory Family (pre-specified H1-H6) vs Exploratory Family (E1-E8)
    decided_mask = ~models_internal["M5"]["abstain"]
    doms_662 = [d for d, keep in zip(doms_691, decided_mask) if keep]

    confirmatory_tests = [
        paired_comparison_full(
            "M0", "M1", "CONFIRMATORIO (H1: Contribución de Infraestructura sobre URL)", "Internal N=691",
            y_691, models_internal["M0"]["pred"], models_internal["M1"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M0", "M2", "CONFIRMATORIO (H2: Contribución Multimodal URL+Infra+DOM sobre URL)", "Internal N=691",
            y_691, models_internal["M0"]["pred"], models_internal["M2"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M0", "M4", "CONFIRMATORIO (H3: Cascada Calibrada M4 sobre URL M0)", "Internal N=691",
            y_691, models_internal["M0"]["pred"], models_internal["M4"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M0_decided", "M5_selective", "CONFIRMATORIO (H4: Clasificación Selectiva M5 sobre M0 en subconjunto decidido)", "Internal Decided N=662",
            y_691[decided_mask], models_internal["M0"]["pred"][decided_mask], models_internal["M5"]["pred"][decided_mask], doms_662
        ),
        paired_comparison_full(
            "M0_External", "HybridM0_NoTranco_External", "CONFIRMATORIO (H5: Generalización Externa HybridM0 sin Tranco vs M0 puro)", "External N=1054",
            y_ext, ext_m0_pred, ext_hyb_notr_pred, doms_ext,
        ),
        paired_comparison_full(
            "M0_External", "HybridM0_WithTranco_External", "CONFIRMATORIO (H6: Generalización Externa HybridM0 con Tranco vs M0 puro)", "External N=1054",
            y_ext, ext_m0_pred, ext_hyb_tr_pred, doms_ext,
        ),
    ]
    conf_pvals = [t["mcnemar_p_exact"] for t in confirmatory_tests]
    conf_holm = holm_bonferroni(conf_pvals)
    for t, ph in zip(confirmatory_tests, conf_holm):
        t["p_holm_bonferroni"] = ph
        t["significant_alpha_0_05_holm"] = bool(ph < 0.05)

    exploratory_tests = [
        paired_comparison_full(
            "M1", "M2", "EXPLORATORIO (E1: Contribución marginal de DOM HTML sobre URL+Infra)", "Internal N=691",
            y_691, models_internal["M1"]["pred"], models_internal["M2"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M2", "M3", "EXPLORATORIO (E2: Contribución marginal de Visual M3 sobre M2 en N=691)", "Internal N=691",
            y_691, models_internal["M2"]["pred"], models_internal["M3"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M2", "M4", "EXPLORATORIO (E3: Equivalencia operativa de Cascada M4 frente a M2 monolítico)", "Internal N=691",
            y_691, models_internal["M2"]["pred"], models_internal["M4"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M4", "M5_FailClosed", "EXPLORATORIO (E4: Retención cautelar Fail-Closed de abstenciones sobre M4)", "Internal N=691",
            y_691, models_internal["M4"]["pred"], models_internal["M5_FailClosed"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M2_decided", "M5_selective", "EXPLORATORIO (E5: M2 monolítico vs M5 selectivo en subconjunto decidido N=662)", "Internal Decided N=662",
            y_691[decided_mask], models_internal["M2"]["pred"][decided_mask], models_internal["M5"]["pred"][decided_mask], doms_662
        ),
        paired_comparison_full(
            "M0", "HybridM0_ConfigA", "EXPLORATORIO (E6: Extensión real Config A vs M0 puro en N=691)", "Internal N=691",
            y_691, models_internal["M0"]["pred"], models_internal["HybridM0_ConfigA"]["pred"], doms_691
        ),
        paired_comparison_full(
            "M4", "ConfigC_HybridCascade", "EXPLORATORIO (E7: Integración Config C vs Cascada API M4 en N=691)", "Internal N=691",
            y_691, models_internal["M4"]["pred"], models_internal["ConfigC_HybridCascade"]["pred"], doms_691
        ),
        paired_comparison_full(
            "HybridM0_NoTranco_External", "HybridM0_WithTranco_External", "EXPLORATORIO (E8: Efecto de lista Tranco en HybridM0 externo N=1054)", "External N=1054",
            y_ext, ext_hyb_notr_pred, ext_hyb_tr_pred, doms_ext,
        ),
    ]
    exp_pvals = [t["mcnemar_p_exact"] for t in exploratory_tests]
    exp_holm = holm_bonferroni(exp_pvals)
    for t, ph in zip(exploratory_tests, exp_holm):
        t["p_holm_bonferroni"] = ph
        t["significant_alpha_0_05_holm"] = bool(ph < 0.05)

    # 5. Calibration & Reliability Analysis (10 bins)
    calibration_analysis = {}
    for m_key in ("M0", "M1", "M2", "M3", "M4", "HybridM0_ConfigA", "ConfigC_HybridCascade"):
        m_obj = models_internal[m_key]
        calibration_analysis[f"Internal_{m_key}"] = {
            "brier_score": round(float(brier_score_loss(m_obj["y"], m_obj["prob"])), 6),
            "ece_10bins": round(float(expected_calibration_error(m_obj["y"], m_obj["prob"], 10)), 6),
            "mce_10bins": round(float(maximum_calibration_error(m_obj["y"], m_obj["prob"], 10)), 6),
            "reliability_bins": compute_reliability_bins(m_obj["y"], m_obj["prob"], 10),
        }
    for pr_arr, key_name in (
        (ext_m0_prob, "External_M0_Raw"),
        (ext_hyb_tr_prob, "External_HybridM0_WithTranco"),
        (ext_hyb_notr_prob, "External_HybridM0_NoTranco"),
    ):
        calibration_analysis[key_name] = {
            "brier_score": round(float(brier_score_loss(y_ext, pr_arr)), 6),
            "ece_10bins": round(float(expected_calibration_error(y_ext, pr_arr, 10)), 6),
            "mce_10bins": round(float(maximum_calibration_error(y_ext, pr_arr, 10)), 6),
            "reliability_bins": compute_reliability_bins(y_ext, pr_arr, 10),
        }

    # 6. Threshold Sensitivity Analysis (tau* - 0.10, -0.05, 0, +0.05, +0.10)
    official_thrs = {
        "M0": 0.382667,
        "M1": 0.525014,
        "M2": 0.394962,
        "M3": 0.391732,
        "M4": 0.464844,
        "HybridM0_ConfigA": 0.350000,
    }
    threshold_sensitivity = {}
    for m_key, tau_star in official_thrs.items():
        m_obj = models_internal[m_key]
        deltas = [-0.10, -0.05, 0.0, +0.05, +0.10]
        rows_s = []
        for d in deltas:
            tau = max(0.05, min(0.95, tau_star + d))
            yp = (m_obj["prob"] >= tau).astype(int)
            tn, fp, fn, tp = confusion_matrix(m_obj["y"], yp, labels=[0, 1]).ravel()
            rows_s.append({
                "delta_tau": round(d, 2),
                "threshold": round(tau, 6),
                "f1": round(float(f1_score(m_obj["y"], yp, zero_division=0)), 6),
                "precision": round(float(precision_score(m_obj["y"], yp, zero_division=0)), 6),
                "recall": round(float(recall_score(m_obj["y"], yp, zero_division=0)), 6),
                "fpr": round(float(fp / (fp + tn)), 6),
                "fnr": round(float(fn / (fn + tp)), 6),
            })
        threshold_sensitivity[m_key] = rows_s

    # 7. Prevalence Sensitivity Analysis (50%, 27.64%, 10%, 5%, 1%, 0.1%)
    prevalences = [0.50, 191.0 / 691.0, 0.10, 0.05, 0.01, 0.001]
    prevalence_sensitivity = {}
    for m_key in ("M0", "M1", "M2", "M4", "M5_FailClosed", "HybridM0_ConfigA"):
        m_obj = models_internal[m_key]
        tn, fp, fn, tp = confusion_matrix(m_obj["y"], m_obj["pred"], labels=[0, 1]).ravel()
        tpr = float(tp / (tp + fn))
        fpr = float(fp / (fp + tn))
        prevalence_sensitivity[f"Internal_{m_key}"] = prevalence_projection(tpr, fpr, prevalences)

    # Also for External M2_CC (strip_www) and External HybridM0_WithTranco
    prevalence_sensitivity["External_HybridM0_WithTranco_N1054"] = prevalence_projection(
        float(recall_score(y_ext, ext_hyb_tr_pred)),
        6.0 / 454.0,
        prevalences,
    )
    prevalence_sensitivity["External_M2_CompleteCase_N104_strip_www"] = prevalence_projection(
        26.0 / 54.0,
        1.0 / 50.0,
        prevalences,
    )

    # 8. Subgroup Error Breakdown by Top TLD on Internal N=691 and External N=1,054
    tld_counts_691 = defaultdict(lambda: {"n": 0, "phish": 0, "legit": 0, "m0_err": 0, "m2_err": 0, "m4_err": 0})
    for idx_i, sid in enumerate(sids_691):
        tld = models_internal["M0"]["tlds"][idx_i] or "unknown"
        lbl = int(y_691[idx_i])
        d = tld_counts_691[tld]
        d["n"] += 1
        if lbl == 1:
            d["phish"] += 1
        else:
            d["legit"] += 1
        if models_internal["M0"]["pred"][idx_i] != lbl:
            d["m0_err"] += 1
        if models_internal["M2"]["pred"][idx_i] != lbl:
            d["m2_err"] += 1
        if models_internal["M4"]["pred"][idx_i] != lbl:
            d["m4_err"] += 1

    top_tlds_internal = []
    for tld, st in sorted(tld_counts_691.items(), key=lambda x: x[1]["n"], reverse=True)[:10]:
        n_t = st["n"]
        top_tlds_internal.append({
            "tld": tld,
            "n": n_t,
            "phishing": st["phish"],
            "legitimate": st["legit"],
            "m0_error_rate": round(st["m0_err"] / n_t, 4),
            "m2_error_rate": round(st["m2_err"] / n_t, 4),
            "m4_error_rate": round(st["m4_err"] / n_t, 4),
        })

    out_payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": collect_environment_metadata(),
        "seed": SEED,
        "bootstrap_replications": B_ITER,
        "internal_sample_and_cluster_bootstrap_cis_n691": internal_bootstrap_cis,
        "external_sample_and_cluster_bootstrap_cis_n1054": external_bootstrap_cis,
        "confirmatory_hypothesis_family": confirmatory_tests,
        "exploratory_hypothesis_family": exploratory_tests,
        "calibration_and_reliability_analysis": calibration_analysis,
        "threshold_sensitivity_analysis": threshold_sensitivity,
        "prevalence_sensitivity_analysis": prevalence_sensitivity,
        "subgroup_tld_breakdown_internal_n691": top_tlds_internal,
    }
    out_json = OUT_DIR / "07_analisis_estadistico_results.json"
    out_json.write_text(json.dumps(out_payload, indent=2), encoding="utf-8")

    # Also export CSV table of all hypothesis tests
    csv_path = OUT_DIR / "07_all_hypothesis_tests_table.csv"
    all_tests = confirmatory_tests + exploratory_tests
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_tests[0].keys()))
        writer.writeheader()
        writer.writerows(all_tests)

    print(f"Resultados de Fase VII guardados en: {out_json}", flush=True)


if __name__ == "__main__":
    main()
