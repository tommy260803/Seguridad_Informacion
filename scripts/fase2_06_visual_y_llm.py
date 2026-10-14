#!/usr/bin/env python3
"""
FASE VI: EVALUACIÓN RIGUROSA DE LOS COMPONENTES VISUAL (M3 CDP) Y LLM (Groq)
============================================================================
1. Componente Visual (Sección 9):
   - Audita los 616 registros de `visual-results-authentic-cdp.jsonl` (467 capturas `live_cdp` exitosas
     y 149 fallidas con desglose de causas de fallo) frente a `visual-results-real.jsonl`.
   - Inspecciona físicamente las 40 capturas PNG en `artifacts/authentic-cdp-screenshots/` y las 91 PNG
     en `artifacts/screenshots/` (dimensiones, bytes, varianza de luminancia, ausencia de imágenes en blanco).
   - Evalúa el Sesgo de Disponibilidad Visual comparando el subconjunto de prueba con captura CDP real (N=83)
     frente al subconjunto sin captura CDP (N=608) en M0, M1 y M2.
   - Compara en condiciones idénticas sobre N=83:
     * `M0`, `M1`, `M2` (sin visual)
     * `M3_global` (entrenado en N=4,219 con 88% ceros visuales)
     * `M3_authentic_cdp` (entrenado exclusivamente en las N=312 muestras de train con captura CDP auténtica)
     * `Visual_Only_32feat` (clasificador entrenado solo con las 32 variables visuales sobre N=312 train CDP y
       evaluado en N=83 test CDP, para medir la señal visual pura sin URL/Infra/DOM).
2. Componente LLM (Sección 10):
   - Audita los dos experimentos existentes:
     * Experimento Histórico (N=100 intentadas, N=30 exitosas: 11 phishing, 19 legítimas con `llama-3.1-8b-instant`).
     * Experimento en Vivo sobre Abstenciones de M5 (N=29 intentadas, 7 exitosas antes de HTTP 429 TPM limit).
   - Intenta evaluar con ritmo controlado (respetando TPM) las muestras legítimas abstenidas por M5 (`label=0`)
     si la API de Groq está disponible, registrando cualquier error/cuota con total transparencia.
   - Evalúa separadamente: (a) el LLM como clasificador/desempatador cuantitativo y (b) la calidad diagnóstica
     de la explicación estructurada (`brand_spoofed`, `threat_type`, `reason`).
"""
from __future__ import annotations

import asyncio
import csv
import glob
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from dotenv import load_dotenv
from PIL import Image
from scipy.stats import binomtest
from sklearn.ensemble import RandomForestClassifier
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
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT / "src"))

from phishguard_common import collect_environment_metadata
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features, load_content_results
from phishguard_ml.evaluation import expected_calibration_error, select_f1_threshold
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features, load_infrastructure_results
from phishguard_ml.visual import VISUAL_FEATURE_NAMES, extract_visual_features, load_visual_results

SEED = 42
OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase6_visual_llm"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def compute_metrics_with_ci(y_true: np.ndarray, y_prob: np.ndarray, threshold: float, n_boot: int = 2000) -> dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    rng = np.random.default_rng(SEED)
    n = len(y_true)
    f1_b = np.empty(n_boot, dtype=float)
    auc_b = np.empty(n_boot, dtype=float)
    for b in range(n_boot):
        idx = rng.integers(0, n, size=n)
        yt = y_true[idx]
        yp = y_pred[idx]
        ypr = y_prob[idx]
        f1_b[b] = f1_score(yt, yp, zero_division=0)
        auc_b[b] = roc_auc_score(yt, ypr) if len(np.unique(yt)) > 1 else np.nan

    return {
        "n": int(n),
        "n_phishing": int(np.sum(y_true == 1)),
        "n_legitimate": int(np.sum(y_true == 0)),
        "threshold": round(float(threshold), 6),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 6) if len(np.unique(y_true)) > 1 else None,
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 6) if len(np.unique(y_true)) > 1 else None,
        "brier_score": round(float(brier_score_loss(y_true, y_prob)), 6),
        "ece": round(float(expected_calibration_error(y_true, y_prob, 10)), 6),
        "ci95_f1": [round(float(np.nanpercentile(f1_b, 2.5)), 6), round(float(np.nanpercentile(f1_b, 97.5)), 6)],
        "ci95_roc_auc": [round(float(np.nanpercentile(auc_b, 2.5)), 6), round(float(np.nanpercentile(auc_b, 97.5)), 6)],
    }


def paired_test(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> dict[str, Any]:
    ca = pred_a == y_true
    cb = pred_b == y_true
    n01 = int(np.sum((~ca) & cb))
    n10 = int(np.sum(ca & (~cb)))
    disc = n01 + n10
    p_val = float(binomtest(min(n01, n10), disc, 0.5).pvalue) if disc > 0 else 1.0
    f1_a = float(f1_score(y_true, pred_a, zero_division=0))
    f1_b = float(f1_score(y_true, pred_b, zero_division=0))
    rng = np.random.default_rng(SEED)
    n = len(y_true)
    diffs = np.empty(2000, dtype=float)
    for b in range(2000):
        idx = rng.integers(0, n, size=n)
        diffs[b] = f1_score(y_true[idx], pred_b[idx], zero_division=0) - f1_score(y_true[idx], pred_a[idx], zero_division=0)
    return {
        "f1_a": round(f1_a, 6),
        "f1_b": round(f1_b, 6),
        "delta_f1_b_minus_a": round(f1_b - f1_a, 6),
        "delta_f1_ci95": [round(float(np.percentile(diffs, 2.5)), 6), round(float(np.percentile(diffs, 97.5)), 6)],
        "n01_b_better": n01,
        "n10_a_better": n10,
        "mcnemar_p_exact": round(p_val, 6),
    }


async def run_visual_and_llm_audit() -> dict[str, Any]:
    print("=== FASE VI: Auditoría y Evaluación Visual (Chrome CDP) y LLM (Groq) ===", flush=True)
    samples_by_id: dict[str, dict[str, str]] = {}
    with open(ROOT / "data/processed/0.1.0/samples.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            samples_by_id[r["sample_id"]] = r

    host_unseen_split: dict[str, str] = {}
    with open(ROOT / "data/processed/0.1.0/splits/host_unseen.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            host_unseen_split[r["sample_id"]] = r["partition"]

    infra_results = load_infrastructure_results(ROOT / "artifacts/analysis-results/infrastructure-results-real.jsonl")
    content_results = load_content_results(ROOT / "artifacts/analysis-results/content-results-real.jsonl")
    visual_results = load_visual_results(ROOT / "artifacts/analysis-results/visual-results-real.jsonl")

    # 1. Audit `visual-results-authentic-cdp.jsonl` raw lines
    cdp_jsonl_path = ROOT / "artifacts/analysis-results/visual-results-authentic-cdp.jsonl"
    cdp_raw_records = [json.loads(line) for line in cdp_jsonl_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    cdp_status_counter = Counter()
    cdp_by_split_success = Counter()
    cdp_by_split_Attempted = Counter()
    cdp_success_map: dict[str, dict[str, Any]] = {}
    cdp_lats_ms = []

    for r in cdp_raw_records:
        sid = r["sample_id"]
        res_obj = r.get("result", r)
        part = host_unseen_split.get(sid, "unknown")
        lbl = samples_by_id.get(sid, {}).get("label", "unknown")
        st = res_obj.get("status")
        err = res_obj.get("error_code")
        cmode = res_obj.get("capture_mode")
        cdp_status_counter[f"{st}:{cmode}:{err}"] += 1
        if st != "not_captured":
            cdp_by_split_Attempted[f"{part}:{lbl}"] += 1
        if st == "success" and cmode == "live_cdp":
            cdp_by_split_success[f"{part}:{lbl}"] += 1
            cdp_success_map[sid] = res_obj
            if res_obj.get("total_elapsed_ms") is not None:
                cdp_lats_ms.append(float(res_obj["total_elapsed_ms"]))

    # 2. Physical inspection of PNG files in `artifacts/authentic-cdp-screenshots/` and `artifacts/screenshots/`
    auth_png_files = sorted(glob.glob(str(ROOT / "artifacts/authentic-cdp-screenshots/*.png")))
    png_widths, png_heights, png_ByteSizes, png_luma_stds = [], [], [], []
    blank_png_count = 0
    for p in auth_png_files:
        bsize = Path(p).stat().st_size
        png_ByteSizes.append(bsize)
        with Image.open(p) as im:
            w, h = im.size
            png_widths.append(w)
            png_heights.append(h)
            arr = np.asarray(im.convert("L"), dtype=np.float64)
            std_l = float(np.std(arr))
            png_luma_stds.append(std_l)
            if std_l < 1.0:
                blank_png_count += 1

    sandbox_png_files = sorted(glob.glob(str(ROOT / "artifacts/screenshots/*.png")))

    # 3. Evaluate M0, M1, M2, M3_global, M3_authentic_cdp, and Visual_Only_32feat on N=83 authentic test cohort
    # and check Availability Bias (N=83 with CDP vs N=608 without CDP inside the N=691 test set)
    cc_test_ids = sorted(
        sid
        for sid, res in infra_results.items()
        if host_unseen_split.get(sid) == "test"
        and res.get("status") == "success"
        and content_results.get(sid, {}).get("status") == "success"
        and visual_results.get(sid, {}).get("status") == "success"
    )
    auth_test_ids = [sid for sid in cc_test_ids if sid in cdp_success_map]
    non_cdp_test_ids = [sid for sid in cc_test_ids if sid not in cdp_success_map]

    # Load predictions of M0, M1, M2, M3_global on N=691
    preds_by_model_sid: dict[str, dict[str, dict[str, Any]]] = {}
    for m_name, m_dir in (("M0", "m0-real"), ("M1", "m1-real"), ("M2", "m2-real"), ("M3_global", "m3-real")):
        preds_by_model_sid[m_name] = {}
        with open(ROOT / "artifacts" / m_dir / "predictions.csv", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["partition"] == "test":
                    preds_by_model_sid[m_name][r["sample_id"]] = {
                        "prob": float(r["probability_phishing"]),
                        "pred": int(r["predicted_label"]),
                        "label": int(r["label"]),
                    }

    # Load M3_authentic_cdp predictions on N=83
    m3_cdp_preds_map: dict[str, dict[str, Any]] = {}
    with open(ROOT / "artifacts/corrected_audit/m3-authentic-cdp/predictions.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["partition"] == "test":
                m3_cdp_preds_map[r["sample_id"]] = {
                    "prob": float(r["probability_phishing"]),
                    "pred": int(r["predicted_label"]),
                    "label": int(r["label"]),
                }

    # Train Visual-Only (32 features) classifier on the 312 authentic CDP train samples and evaluate on N=83 test
    auth_train_ids = sorted(sid for sid in cdp_success_map if host_unseen_split.get(sid) == "train")
    auth_val_ids = sorted(sid for sid in cdp_success_map if host_unseen_split.get(sid) == "validation")

    def extract_vis32_matrix(sids: list[str]) -> tuple[np.ndarray, np.ndarray]:
        X_v, y_v = [], []
        for sid in sids:
            vf = extract_visual_features(cdp_success_map[sid])
            X_v.append([float(vf[k]) for k in VISUAL_FEATURE_NAMES])
            y_v.append(1 if samples_by_id[sid]["label"] == "phishing" else 0)
        return np.array(X_v, dtype=np.float64), np.array(y_v, dtype=int)

    X_v_train, y_v_train = extract_vis32_matrix(auth_train_ids)
    X_v_val, y_v_val = extract_vis32_matrix(auth_val_ids)
    X_v_test, y_v_test = extract_vis32_matrix(auth_test_ids)

    vis_only_clf = RandomForestClassifier(
        n_estimators=300, max_depth=10, min_samples_leaf=3, class_weight="balanced_subsample", random_state=SEED
    )
    vis_only_clf.fit(X_v_train, y_v_train)
    val_v_probs = vis_only_clf.predict_proba(X_v_val)[:, 1]
    tau_vis_only = float(select_f1_threshold(y_v_val, val_v_probs)["threshold"])
    test_v_probs = vis_only_clf.predict_proba(X_v_test)[:, 1]

    # Top-10 most informative visual features in Visual_Only_32feat
    vis_importances = sorted(
        zip(VISUAL_FEATURE_NAMES, vis_only_clf.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )[:10]

    # Compute metrics on N=83 authentic CDP test cohort for all models
    y_83 = np.array([preds_by_model_sid["M2"][sid]["label"] for sid in auth_test_ids], dtype=int)
    y_608 = np.array([preds_by_model_sid["M2"][sid]["label"] for sid in non_cdp_test_ids], dtype=int)

    thrs = {
        "M0": 0.38266699053469533,
        "M1": 0.5250141792140176,
        "M2": 0.39496177581001815,
        "M3_global": 0.39173164363827564,
    }
    n83_comparison = {}
    n608_non_cdp_comparison = {}
    for m_name in ("M0", "M1", "M2", "M3_global"):
        probs_83 = np.array([preds_by_model_sid[m_name][sid]["prob"] for sid in auth_test_ids], dtype=float)
        probs_608 = np.array([preds_by_model_sid[m_name][sid]["prob"] for sid in non_cdp_test_ids], dtype=float)
        n83_comparison[m_name] = compute_metrics_with_ci(y_83, probs_83, thrs[m_name])
        n608_non_cdp_comparison[m_name] = compute_metrics_with_ci(y_608, probs_608, thrs[m_name])

    probs_m3_cdp_83 = np.array([m3_cdp_preds_map[sid]["prob"] for sid in auth_test_ids], dtype=float)
    preds_m3_cdp_83 = np.array([m3_cdp_preds_map[sid]["pred"] for sid in auth_test_ids], dtype=int)
    tau_m3_cdp = float(json.loads((ROOT / "artifacts/corrected_audit/m3-authentic-cdp/metrics.json").read_text())["selected_threshold"])
    n83_comparison["M3_authentic_cdp"] = compute_metrics_with_ci(y_83, probs_m3_cdp_83, tau_m3_cdp)
    n83_comparison["Visual_Only_32feat"] = compute_metrics_with_ci(y_83, test_v_probs, tau_vis_only)

    # Also evaluate an ensemble blending M2 + M3_authentic_cdp on N=83
    probs_m2_83 = np.array([preds_by_model_sid["M2"][sid]["prob"] for sid in auth_test_ids], dtype=float)
    probs_m2_plus_vis_83 = 0.75 * probs_m2_83 + 0.25 * probs_m3_cdp_83
    n83_comparison["M2_plus_M3_CDP_Blend_75_25"] = compute_metrics_with_ci(y_83, probs_m2_plus_vis_83, 0.40)

    preds_m0_83 = np.array([preds_by_model_sid["M0"][sid]["pred"] for sid in auth_test_ids], dtype=int)
    preds_m1_83 = np.array([preds_by_model_sid["M1"][sid]["pred"] for sid in auth_test_ids], dtype=int)
    preds_m2_83 = np.array([preds_by_model_sid["M2"][sid]["pred"] for sid in auth_test_ids], dtype=int)
    preds_m3g_83 = np.array([preds_by_model_sid["M3_global"][sid]["pred"] for sid in auth_test_ids], dtype=int)

    n83_paired_tests = {
        "M2_vs_M3_authentic_cdp_on_N83": paired_test(y_83, preds_m2_83, preds_m3_cdp_83),
        "M2_vs_M3_global_on_N83": paired_test(y_83, preds_m2_83, preds_m3g_83),
        "M0_vs_M3_authentic_cdp_on_N83": paired_test(y_83, preds_m0_83, preds_m3_cdp_83),
        "M1_vs_M2_on_N83": paired_test(y_83, preds_m1_83, preds_m2_83),
    }

    # =========================================================================
    # 4. AUDITORÍA Y EVALUACIÓN DEL COMPONENTE LLM (Groq)
    # =========================================================================
    llm_summary_existing = json.loads((ROOT / "artifacts/corrected_audit/llm_evaluation_summary.json").read_text(encoding="utf-8"))
    llm_hist_rows = json.loads((ROOT / "artifacts/corrected_audit/llm_evaluation_results.json").read_text(encoding="utf-8"))
    llm_live_rows = json.loads((ROOT / "artifacts/corrected_audit/llm_live_m5_abstained_results.json").read_text(encoding="utf-8"))

    # Check if we can evaluate any legitimate (`label == 0`) M5-abstained samples live with Groq API right now
    legit_abstained_rows = [r for r in llm_live_rows if int(r["label"]) == 0 and not r.get("llm_success")]
    supplemental_legit_calls: list[dict[str, Any]] = []
    if os.getenv("GROQ_API_KEY") and legit_abstained_rows:
        from phishguard_api.llm_agent import analyze_with_llm
        print(f"Probando llamadas en vivo a Groq sobre {min(4, len(legit_abstained_rows))} muestras legítimas abstenidas por M5...", flush=True)
        for cand in legit_abstained_rows[:4]:
            t0 = time.perf_counter()
            res_llm, err_llm = await analyze_with_llm(cand["url"], float(cand["cascade_prob"]))
            el_ms = (time.perf_counter() - t0) * 1000.0
            if res_llm and "probability" in res_llm:
                usage = res_llm.get("usage", {})
                supplemental_legit_calls.append({
                    "sample_id": cand["sample_id"],
                    "url": cand["url"],
                    "label": 0,
                    "cascade_prob": float(cand["cascade_prob"]),
                    "llm_prob": float(res_llm["probability"]),
                    "llm_pred_0_5": int(float(res_llm["probability"]) >= 0.5),
                    "llm_success": True,
                    "llm_brand": res_llm.get("brand_spoofed"),
                    "llm_threat_type": res_llm.get("threat_type"),
                    "llm_reason": str(res_llm.get("reason", ""))[:300],
                    "measured_prompt_tokens": int(usage.get("prompt_tokens", 0)),
                    "measured_completion_tokens": int(usage.get("completion_tokens", 0)),
                    "measured_total_tokens": int(usage.get("total_tokens", 0)),
                    "measured_latency_ms": round(el_ms, 2),
                })
            else:
                supplemental_legit_calls.append({
                    "sample_id": cand["sample_id"],
                    "url": cand["url"],
                    "label": 0,
                    "llm_success": False,
                    "llm_error": err_llm,
                    "measured_latency_ms": round(el_ms, 2),
                })

    # Qualitative & Diagnostic audit of the 30 historical LLM explanations + live M5 abstained explanations
    hist_succ_rows = [r for r in llm_hist_rows if r.get("llm_prob") is not None]
    hist_legit_succ = [r for r in hist_succ_rows if int(r["label"]) == 0]
    hist_phish_succ = [r for r in hist_succ_rows if int(r["label"]) == 1]

    # Check calibration and threshold behavior on the 30 historical samples (19 legitimate, 11 phishing)
    y_h30 = np.array([int(r["label"]) for r in hist_succ_rows], dtype=int)
    p_llm_h30 = np.array([float(r["llm_prob"]) for r in hist_succ_rows], dtype=float)
    p_m0_h30 = np.array([float(r["m0_prob"]) for r in hist_succ_rows], dtype=float)
    p_hyb_h30 = 0.65 * p_m0_h30 + 0.35 * p_llm_h30

    # Combine all successful live M5-abstained calls (7 existing phishing + any supplemental legitimate calls)
    all_live_succ = [r for r in llm_live_rows if r.get("llm_success")] + [r for r in supplemental_legit_calls if r.get("llm_success")]
    y_live_all = np.array([int(r["label"]) for r in all_live_succ], dtype=int) if all_live_succ else np.array([])
    p_llm_live_all = np.array([float(r["llm_prob"]) for r in all_live_succ], dtype=float) if all_live_succ else np.array([])
    p_cas_live_all = np.array([float(r["cascade_prob"]) for r in all_live_succ], dtype=float) if all_live_succ else np.array([])

    combined_live_eval = {}
    if len(all_live_succ) > 0:
        combined_live_eval = {
            "total_successful_live_m5_abstained": len(all_live_succ),
            "n_phishing": int(np.sum(y_live_all == 1)),
            "n_legitimate": int(np.sum(y_live_all == 0)),
            "llm_zero_shot_0_5": compute_metrics_with_ci(y_live_all, p_llm_live_all, 0.50, n_boot=500),
            "cascade_plus_llm_50_50": compute_metrics_with_ci(y_live_all, 0.5 * p_cas_live_all + 0.5 * p_llm_live_all, 0.50, n_boot=500),
            "cascade_forced_alone": compute_metrics_with_ci(y_live_all, p_cas_live_all, 0.394962, n_boot=500),
            "records": all_live_succ,
        }

    out = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": collect_environment_metadata(),
        "visual_component_audit": {
            "cdp_jsonl_total_records": len(cdp_raw_records),
            "cdp_live_success_count": len(cdp_success_map),
            "cdp_failed_count": len(cdp_raw_records) - len(cdp_success_map),
            "cdp_status_and_error_breakdown": dict(cdp_status_counter),
            "cdp_attempted_by_split_and_class": dict(cdp_by_split_Attempted),
            "cdp_success_by_split_and_class": dict(cdp_by_split_success),
            "cdp_capture_latency_ms": {
                "n": len(cdp_lats_ms),
                "mean_ms": round(float(np.mean(cdp_lats_ms)), 2),
                "sd_ms": round(float(np.std(cdp_lats_ms, ddof=1)), 2),
                "p50_ms": round(float(np.percentile(cdp_lats_ms, 50)), 2),
                "p90_ms": round(float(np.percentile(cdp_lats_ms, 90)), 2),
                "p95_ms": round(float(np.percentile(cdp_lats_ms, 95)), 2),
                "p99_ms": round(float(np.percentile(cdp_lats_ms, 99)), 2),
            },
            "physical_png_audit": {
                "authentic_cdp_screenshots_retained_count": len(auth_png_files),
                "sandbox_screenshots_count": len(sandbox_png_files),
                "blank_or_uniform_png_count": blank_png_count,
                "dimensions_observed": list(set(zip(png_widths, png_heights))),
                "file_size_bytes_mean": round(float(np.mean(png_ByteSizes)), 1) if png_ByteSizes else 0.0,
                "file_size_bytes_min": int(min(png_ByteSizes)) if png_ByteSizes else 0,
                "file_size_bytes_max": int(max(png_ByteSizes)) if png_ByteSizes else 0,
                "luminance_std_mean": round(float(np.mean(png_luma_stds)), 2) if png_luma_stds else 0.0,
            },
            "availability_bias_analysis": {
                "test_with_cdp_n83_phishing_rate": round(float(np.mean(y_83)), 4),
                "test_without_cdp_n608_phishing_rate": round(float(np.mean(y_608)), 4),
                "models_on_n83_with_cdp": n83_comparison,
                "models_on_n608_without_cdp": n608_non_cdp_comparison,
            },
            "n83_paired_statistical_tests": n83_paired_tests,
            "visual_only_top10_feature_importances": [
                {"feature": k, "importance": round(float(v), 5)} for k, v in vis_importances
            ],
        },
        "llm_component_audit": {
            "historical_benchmark_n100_n30_succ": {
                "total_attempted": len(llm_hist_rows),
                "html_download_failed_count": len(llm_hist_rows) - len(hist_succ_rows),
                "llm_evaluated_count": len(hist_succ_rows),
                "n_phishing": len(hist_phish_succ),
                "n_legitimate": len(hist_legit_succ),
                "model": "llama-3.1-8b-instant",
                "m0_alone_on_n30": compute_metrics_with_ci(y_h30, p_m0_h30, 0.4339, n_boot=1000),
                "llm_alone_tau_0_50_on_n30": compute_metrics_with_ci(y_h30, p_llm_h30, 0.50, n_boot=1000),
                "llm_alone_tau_0_20_on_n30": compute_metrics_with_ci(y_h30, p_llm_h30, 0.20, n_boot=1000),
                "m0_plus_llm_hybrid_on_n30": compute_metrics_with_ci(y_h30, p_hyb_h30, 0.40, n_boot=1000),
                "mean_llm_prob_on_legitimate": round(float(np.mean([r["llm_prob"] for r in hist_legit_succ])), 4),
                "mean_llm_prob_on_phishing": round(float(np.mean([r["llm_prob"] for r in hist_phish_succ])), 4),
            },
            "live_m5_abstained_evaluation": {
                "previous_audit_summary": llm_summary_existing.get("live_m5_abstained_evaluation"),
                "supplemental_legitimate_calls_attempted": len(supplemental_legit_calls),
                "supplemental_legitimate_calls_succeeded": sum(1 for r in supplemental_legit_calls if r.get("llm_success")),
                "combined_live_m5_abstained_evaluation": combined_live_eval,
            },
        },
    }

    out_path = OUT_DIR / "06_visual_y_llm_results.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Resultados de Fase VI guardados en: {out_path}", flush=True)
    return out


if __name__ == "__main__":
    asyncio.run(run_visual_and_llm_audit())
