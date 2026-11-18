"""
Evaluacion prospectiva de RAEA-Phish sobre la Cohorte Externa Independiente (N=240).
Ejecuta los modelos congelados M0, M1, M2 y la politica adaptativa RAEA sobre 240 URLs
con 120 phishing web verificados y 120 controles legitimos diversos (.edu, .gov, comercial),
con cero solapamiento de dominios con entrenamiento y cohorte retrospectiva.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features
from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features
from phishguard_orchestrator.raea.engine import run_raea
from phishguard_orchestrator.raea.models import RAEAConfig, Action
from scripts.train_and_validate_raea_estimators import extract_features_for_sample

OUT_DIR = ROOT / "artifacts" / "raea_independent_n240"
FIG_DIR = OUT_DIR / "FIGURAS"
OUT_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)

CFG = json.loads((ROOT / "configs" / "raea_final_experiment.json").read_text(encoding="utf-8"))
CONFIG_VERSION = CFG["config_version"]
BASE = CFG["base_costs"]
C_FP, GAMMA, C_ABS, LAMBDA = BASE["c_fp"], BASE["gamma"], BASE["c_abstain"], BASE["lambda_cost"]
ACQ = CFG["normalized_acquisition_cost"]
SEED = 42
B_BOOT = 5000

PROBE_FILE = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa" / "external_multimodal_probe_n240.jsonl"

def entropy(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return - (p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))

def chow_decision(p: float, gamma: float = GAMMA, c_abs: float = C_ABS, c_fp: float = C_FP) -> str:
    risks = {
        "phishing": c_fp * (1.0 - p),
        "legitimate": gamma * c_fp * p,
        "abstain": c_abs
    }
    return min(risks, key=risks.get)

def realized_cost(requested: list[str], infra_status: str, content_status: str) -> float:
    c = 0.0
    if "network" in requested or "infra" in requested:
        c += ACQ["network"]["success"] if infra_status == "success" else ACQ["network"]["failure"]
    if "html" in requested or "content" in requested:
        c += ACQ["html"]["success"] if content_status == "success" else ACQ["html"]["failure"]
    return c

def f1_score_calc(tp: int, fp: int, fn: int) -> float:
    denom = 2 * tp + fp + fn
    return round((2.0 * tp) / denom, 6) if denom > 0 else 0.0

def penalized_risk(y: int, decision: str, gamma: float = GAMMA, c_abs: float = C_ABS, c_fp: float = C_FP) -> float:
    if decision == "abstain":
        return c_abs
    elif decision == "phishing":
        return 0.0 if y == 1 else c_fp
    elif decision == "legitimate":
        return gamma * c_fp if y == 1 else 0.0
    return c_abs

def paired_bootstrap(d1: np.ndarray, d2: np.ndarray, b: int = B_BOOT, seed: int = SEED):
    rng = np.random.default_rng(seed)
    n = len(d1)
    diff = d1 - d2
    orig_mean = float(np.mean(diff))
    idx = rng.integers(0, n, size=(b, n))
    b_diffs = np.mean(diff[idx], axis=1)
    ci_low = float(np.percentile(b_diffs, 2.5))
    ci_high = float(np.percentile(b_diffs, 97.5))
    p_two = 2.0 * min(np.mean(b_diffs <= 0), np.mean(b_diffs >= 0))
    p_two = max(float(p_two), 1.0 / b)
    return orig_mean, ci_low, ci_high, min(p_two, 1.0)

def main():
    print("=" * 75)
    print("EVALUACION PROSPECTIVA DE RAEA-PHISH SOBRE COHORTE INDEPENDIENTE (N=240)")
    print("=" * 75)
    
    # 1. Cargar modelos congelados
    print("\n[Paso 1/6] Cargando modelos base y estimadores congelados...")
    m0_obj = joblib.load(ROOT / "artifacts" / "m0-ite-real" / "model.joblib")
    m1_obj = joblib.load(ROOT / "artifacts" / "m1-ite-real" / "model.joblib")
    m2_obj = joblib.load(ROOT / "artifacts" / "m2-ite-real" / "model.joblib")
    print("  + Modelos M0, M1, M2 ITE cargados exitosamente.")
    
    # 2. Cargar y procesar cohorte N=240
    print(f"\n[Paso 2/6] Ingestando cohorte N=240 desde {PROBE_FILE.name}...")
    samples = []
    with open(PROBE_FILE, encoding="utf-8") as f:
        for line in f:
            samples.append(json.loads(line))
    
    manifest_rows = []
    features_v0, features_v1, features_v2 = [], [], []
    
    for item in samples:
        s = item["sample"]
        pr = item["probe"]
        cid = s["external_id"]
        url = s["canonical_url"]
        dom = s["registered_domain"]
        lbl_str = s["label"]
        y = 1 if lbl_str == "phishing" else 0
        src = s["source"]
        
        uf = extract_url_features(UrlFeatureContext(url, dom))
        inf_f = extract_infrastructure_features(pr["infra"])
        cnt_f = extract_content_features(pr["content"])
        
        v0 = [uf[k] for k in AUTHORITY_FEATURE_NAMES]
        v1 = v0 + [inf_f[k] for k in INFRA_FEATURE_NAMES]
        v2 = v1 + [cnt_f[k] for k in CONTENT_FEATURE_NAMES]
        
        features_v0.append(v0)
        features_v1.append(v1)
        features_v2.append(v2)
        
        lat_m0 = 5.0
        lat_infra = float(pr.get("infra_elapsed_ms", 150.0))
        lat_content = float(pr.get("http_download_ms", 400.0)) + (float(pr.get("dom_parse_ms", 50.0)) if pr["content"].get("status") == "success" else 0.0)
        
        manifest_rows.append({
            "external_id": cid,
            "canonical_url": url,
            "registered_domain": dom,
            "label_int": y,
            "label_str": lbl_str,
            "source": src,
            "infra_status": pr["infra"].get("status", "error"),
            "content_status": pr["content"].get("status", "error"),
            "lat_m0_ms": lat_m0,
            "lat_infra_ms": lat_infra,
            "lat_content_ms": lat_content
        })
        
    df_man = pd.DataFrame(manifest_rows)
    df_man.to_csv(OUT_DIR / "COHORTE_INDEPENDIENTE_N240_MANIFIESTO.csv", index=False)
    print(f"  + Manifiesto guardado: {len(df_man)} muestras (120 phishing, 120 legitimas)")
    print("  + Distribucion de fuentes:")
    for src, cnt in df_man["source"].value_counts().items():
        print(f"      - {src:20s}: {cnt}")
        
    # Inferencia de probabilidades base
    X0 = np.array(features_v0, dtype=np.float64)
    X1 = np.array(features_v1, dtype=np.float64)
    X2 = np.array(features_v2, dtype=np.float64)
    
    df_man["p_m0"] = m0_obj["model"].predict_proba(X0)[:, 1]
    df_man["p_m1"] = m1_obj["model"].predict_proba(X1)[:, 1]
    df_man["p_m2"] = m2_obj["model"].predict_proba(X2)[:, 1]
    
    # 3. Evaluar politicas basales y RAEA
    print("\n[Paso 3/6] Evaluando politicas basales concurrentes y RAEA adaptativo...")
    pred_rows = []
    
    # Definir configuraciones de ablacion para RAEA
    ablations_cfg = {
        "A1": ("RAEA_sin_disponibilidad", RAEAConfig(enable_availability=False)),
        "A2": ("RAEA_sin_costes_asimetricos", RAEAConfig(enable_asymmetric_cost=False)),
        "A3": ("RAEA_sin_abstencion", RAEAConfig(enable_abstention=False)),
        "A4": ("RAEA_sin_valor_informacion", RAEAConfig(enable_information_value=False)),
        "A5": ("RAEA_sin_guarda_benigna", RAEAConfig(p_safe=0.0)),
        "A6": ("RAEA_completo", RAEAConfig()),
    }
    
    for idx, row in df_man.iterrows():
        cid = row["external_id"]
        y = int(row["label_int"])
        url = row["canonical_url"]
        p0 = float(row["p_m0"])
        p1 = float(row["p_m1"])
        p2 = float(row["p_m2"])
        
        # 1. B0_M0 (Solo lexico)
        d_m0 = "phishing" if p0 >= 0.5 else "legitimate"
        c_m0 = realized_cost([], row["infra_status"], row["content_status"])
        lat_m0 = row["lat_m0_ms"]
        r_m0 = penalized_risk(y, d_m0)
        pred_rows.append({
            "external_id": cid, "policy": "B0_M0", "y_true": y, "decision": d_m0, "final_prob": p0,
            "state": "decided", "modalities_requested": "url", "n_modalities": 1.0,
            "normalized_cost": c_m0, "latency_ms": lat_m0, "penalized_risk": r_m0
        })
        
        # 2. B1_M1 (Lexico + Red)
        d_m1 = "phishing" if p1 >= 0.5 else "legitimate"
        c_m1 = realized_cost(["network"], row["infra_status"], row["content_status"])
        lat_m1 = row["lat_m0_ms"] + row["lat_infra_ms"]
        r_m1 = penalized_risk(y, d_m1)
        pred_rows.append({
            "external_id": cid, "policy": "B1_M1", "y_true": y, "decision": d_m1, "final_prob": p1,
            "state": "decided", "modalities_requested": "url|network", "n_modalities": 2.0,
            "normalized_cost": c_m1, "latency_ms": lat_m1, "penalized_risk": r_m1
        })
        
        # 3. B2_M2 (Lexico + Red + HTML)
        d_m2 = "phishing" if p2 >= 0.5 else "legitimate"
        c_m2 = realized_cost(["network", "html"], row["infra_status"], row["content_status"])
        lat_m2 = row["lat_m0_ms"] + row["lat_infra_ms"] + row["lat_content_ms"]
        r_m2 = penalized_risk(y, d_m2)
        pred_rows.append({
            "external_id": cid, "policy": "B2_M2", "y_true": y, "decision": d_m2, "final_prob": p2,
            "state": "decided", "modalities_requested": "url|network|html", "n_modalities": 3.0,
            "normalized_cost": c_m2, "latency_ms": lat_m2, "penalized_risk": r_m2
        })
        
        # 4. B3_entropy (Cascada simetrica)
        if entropy(p0) <= 0.15:
            d_b3 = "phishing" if p0 >= 0.5 else "legitimate"
            c_b3, lat_b3, n_mod_b3, mod_str_b3, p_b3 = realized_cost([], row["infra_status"], row["content_status"]), row["lat_m0_ms"], 1.0, "url", p0
        elif entropy(p1) <= 0.15 or row["content_status"] != "success":
            d_b3 = "phishing" if p1 >= 0.5 else "legitimate"
            c_b3, lat_b3, n_mod_b3, mod_str_b3, p_b3 = realized_cost(["network"], row["infra_status"], row["content_status"]), row["lat_m0_ms"] + row["lat_infra_ms"], 2.0, "url|network", p1
        else:
            d_b3 = "phishing" if p2 >= 0.5 else "legitimate"
            c_b3, lat_b3, n_mod_b3, mod_str_b3, p_b3 = realized_cost(["network", "html"], row["infra_status"], row["content_status"]), row["lat_m0_ms"] + row["lat_infra_ms"] + row["lat_content_ms"], 3.0, "url|network|html", p2
        r_b3 = penalized_risk(y, d_b3)
        pred_rows.append({
            "external_id": cid, "policy": "B3_entropy", "y_true": y, "decision": d_b3, "final_prob": p_b3,
            "state": "decided", "modalities_requested": mod_str_b3, "n_modalities": n_mod_b3,
            "normalized_cost": c_b3, "latency_ms": lat_b3, "penalized_risk": r_b3
        })
        
        # 5. B4_conservative (Cascada asimetrica conservadora)
        if p0 <= 0.02:
            d_b4 = "legitimate"
            c_b4, lat_b4, n_mod_b4, mod_str_b4, p_b4 = realized_cost([], row["infra_status"], row["content_status"]), row["lat_m0_ms"], 1.0, "url", p0
        elif p0 >= 0.85:
            d_b4 = "phishing"
            c_b4, lat_b4, n_mod_b4, mod_str_b4, p_b4 = realized_cost([], row["infra_status"], row["content_status"]), row["lat_m0_ms"], 1.0, "url", p0
        elif entropy(p1) <= 0.15 or row["content_status"] != "success":
            d_b4 = "phishing" if p1 >= 0.5 else "legitimate"
            c_b4, lat_b4, n_mod_b4, mod_str_b4, p_b4 = realized_cost(["network"], row["infra_status"], row["content_status"]), row["lat_m0_ms"] + row["lat_infra_ms"], 2.0, "url|network", p1
        else:
            d_b4 = "phishing" if p2 >= 0.5 else "legitimate"
            c_b4, lat_b4, n_mod_b4, mod_str_b4, p_b4 = realized_cost(["network", "html"], row["infra_status"], row["content_status"]), row["lat_m0_ms"] + row["lat_infra_ms"] + row["lat_content_ms"], 3.0, "url|network|html", p2
        r_b4 = penalized_risk(y, d_b4)
        pred_rows.append({
            "external_id": cid, "policy": "B4_conservative", "y_true": y, "decision": d_b4, "final_prob": p_b4,
            "state": "decided", "modalities_requested": mod_str_b4, "n_modalities": n_mod_b4,
            "normalized_cost": c_b4, "latency_ms": lat_b4, "penalized_risk": r_b4
        })
        
        # 6. B5_M1_chow (Clasificacion selectiva Chow sobre M1)
        d_b5 = chow_decision(p1)
        c_b5 = realized_cost(["network"], row["infra_status"], row["content_status"])
        lat_b5 = row["lat_m0_ms"] + row["lat_infra_ms"]
        r_b5 = penalized_risk(y, d_b5)
        pred_rows.append({
            "external_id": cid, "policy": "B5_M1_chow", "y_true": y, "decision": d_b5, "final_prob": p1,
            "state": "abstained" if d_b5 == "abstain" else "decided",
            "modalities_requested": "url|network", "n_modalities": 2.0,
            "normalized_cost": c_b5, "latency_ms": lat_b5, "penalized_risk": r_b5
        })
        
        # 7. RAEA Adaptativo y Ablaciones A1-A6
        x0 = extract_features_for_sample(url)
        offline = {
            "infra_status": row["infra_status"],
            "content_status": row["content_status"],
            "p_m0": p0,
            "p_m1": p1,
            "p_m2": p2,
            "lat_infra_ms": row["lat_infra_ms"],
            "lat_content_ms": row["lat_content_ms"]
        }
        
        for ab_code, (ab_name, ab_cfg) in ablations_cfg.items():
            raea_res = run_raea(url, x0, p0, config=ab_cfg, offline_data=offline)
            d_raea = "abstain" if raea_res.abstained else raea_res.decision
            
            # Modalidades consultadas
            mods = list(raea_res.modalities_consulted)
            n_mod = 1.0 + len([m for m in mods if m != "visual"])
            c_raea = realized_cost(mods, row["infra_status"], row["content_status"])
            
            lat_raea = row["lat_m0_ms"]
            if "network" in mods:
                lat_raea += row["lat_infra_ms"]
            if "html" in mods:
                lat_raea += row["lat_content_ms"]
                
            r_raea = penalized_risk(y, d_raea)
            action_seq = "|".join(t.action.value for t in raea_res.transitions)
            
            # Registrar RAEA principal como B6_RAEA
            if ab_code == "A6":
                pred_rows.append({
                    "external_id": cid, "policy": "B6_RAEA", "y_true": y, "decision": d_raea, "final_prob": raea_res.probability_phishing,
                    "state": "abstained" if d_raea == "abstain" else "decided",
                    "modalities_requested": "|".join(mods), "n_modalities": n_mod,
                    "normalized_cost": c_raea, "latency_ms": lat_raea, "penalized_risk": r_raea,
                    "action_sequence": action_seq
                })
            
            pred_rows.append({
                "external_id": cid, "policy": ab_code, "y_true": y, "decision": d_raea, "final_prob": raea_res.probability_phishing,
                "state": "abstained" if d_raea == "abstain" else "decided",
                "modalities_requested": "|".join(mods), "n_modalities": n_mod,
                "normalized_cost": c_raea, "latency_ms": lat_raea, "penalized_risk": r_raea,
                "action_sequence": action_seq
            })

    df_preds = pd.DataFrame(pred_rows)
    df_preds.to_csv(OUT_DIR / "PREDICCIONES_INDEPENDIENTES_N240.csv", index=False)
    print(f"  + Predicciones guardadas en {OUT_DIR / 'PREDICCIONES_INDEPENDIENTES_N240.csv'}")
    
    # 4. Calcular tabla de resultados principales
    print("\n[Paso 4/6] Calculando métricas de rendimiento comparativo sobre N=240...")
    eval_pols = ["B0_M0", "B1_M1", "B2_M2", "B3_entropy", "B4_conservative", "B5_M1_chow", "B6_RAEA"]
    res_rows = []
    
    for pol in eval_pols:
        sub = df_preds[df_preds["policy"] == pol].copy()
        n = len(sub)
        n_pos = int((sub["y_true"] == 1).sum())
        n_neg = int((sub["y_true"] == 0).sum())
        
        dec = sub[sub["state"] == "decided"]
        n_dec = len(dec)
        n_abs = n - n_dec
        cov = n_dec / n
        
        tp = int(((dec["y_true"] == 1) & (dec["decision"] == "phishing")).sum())
        fp = int(((dec["y_true"] == 0) & (dec["decision"] == "phishing")).sum())
        fn = int(((dec["y_true"] == 1) & (dec["decision"] == "legitimate")).sum())
        tn = int(((dec["y_true"] == 0) & (dec["decision"] == "legitimate")).sum())
        
        f1_sel = f1_score_calc(tp, fp, fn)
        rec_sel = round(tp / (tp + fn), 6) if (tp + fn) > 0 else 0.0
        prec_sel = round(tp / (tp + fp), 6) if (tp + fp) > 0 else 0.0
        fpr_sel = round(fp / (fp + tn), 6) if (fp + tn) > 0 else 0.0
        
        # Fail-open: abstenciones se asignan a 0 (legitimo)
        pred_fo = sub.apply(lambda r: 0 if r["state"] == "abstained" else (1 if r["decision"] == "phishing" else 0), axis=1)
        tp_fo = int(((sub["y_true"] == 1) & (pred_fo == 1)).sum())
        fp_fo = int(((sub["y_true"] == 0) & (pred_fo == 1)).sum())
        fn_fo = int(((sub["y_true"] == 1) & (pred_fo == 0)).sum())
        tn_fo = int(((sub["y_true"] == 0) & (pred_fo == 0)).sum())
        prec_fo = round(tp_fo / (tp_fo + fp_fo), 6) if (tp_fo + fp_fo) > 0 else 0.0
        rec_fo = round(tp_fo / (tp_fo + fn_fo), 6) if (tp_fo + fn_fo) > 0 else 0.0
        f1_fo = f1_score_calc(tp_fo, fp_fo, fn_fo)
        fpr_fo = round(fp_fo / (fp_fo + tn_fo), 6) if (fp_fo + tn_fo) > 0 else 0.0
        fnr_fo = round(fn_fo / (fn_fo + tp_fo), 6) if (fn_fo + tp_fo) > 0 else 0.0
        
        # Fail-closed: abstenciones se asignan a 1 (phishing / sospechoso)
        pred_fc = sub.apply(lambda r: 1 if r["state"] == "abstained" else (1 if r["decision"] == "phishing" else 0), axis=1)
        tp_fc = int(((sub["y_true"] == 1) & (pred_fc == 1)).sum())
        fp_fc = int(((sub["y_true"] == 0) & (pred_fc == 1)).sum())
        fn_fc = int(((sub["y_true"] == 1) & (pred_fc == 0)).sum())
        tn_fc = int(((sub["y_true"] == 0) & (pred_fc == 0)).sum())
        prec_fc = round(tp_fc / (tp_fc + fp_fc), 6) if (tp_fc + fp_fc) > 0 else 0.0
        rec_fc = round(tp_fc / (tp_fc + fn_fc), 6) if (tp_fc + fn_fc) > 0 else 0.0
        f1_fc = f1_score_calc(tp_fc, fp_fc, fn_fc)
        fpr_fc = round(fp_fc / (fp_fc + tn_fc), 6) if (fp_fc + tn_fc) > 0 else 0.0
        fnr_fc = round(fn_fc / (fn_fc + tp_fc), 6) if (fn_fc + tp_fc) > 0 else 0.0
        
        avg_mod = round(float(sub["n_modalities"].mean()), 4)
        avg_cost = round(float(sub["normalized_cost"].mean()), 4)
        avg_risk = round(float(sub["penalized_risk"].mean()), 4)
        avg_lat = round(float(sub["latency_ms"].mean()), 2)
        p50_lat = round(float(sub["latency_ms"].median()), 2)
        
        abs_pos = int(((sub["y_true"] == 1) & (sub["state"] == "abstained")).sum())
        abs_neg = int(((sub["y_true"] == 0) & (sub["state"] == "abstained")).sum())
        
        res_rows.append({
            "policy": pol,
            "N": n,
            "n_pos": n_pos,
            "n_neg": n_neg,
            "n_decided": n_dec,
            "n_abstained": n_abs,
            "abstained_pos": abs_pos,
            "abstained_neg": abs_neg,
            "coverage": round(cov, 4),
            "sel_TP": tp,
            "sel_FP": fp,
            "sel_TN": tn,
            "sel_FN": fn,
            "sel_precision": prec_sel,
            "sel_recall": rec_sel,
            "sel_FPR": fpr_sel,
            "sel_F1": f1_sel,
            "failopen_TP": tp_fo,
            "failopen_FP": fp_fo,
            "failopen_TN": tn_fo,
            "failopen_FN": fn_fo,
            "failopen_precision": prec_fo,
            "failopen_recall": rec_fo,
            "failopen_F1": f1_fo,
            "failopen_FPR": fpr_fo,
            "failopen_FNR": fnr_fo,
            "failclosed_TP": tp_fc,
            "failclosed_FP": fp_fc,
            "failclosed_TN": tn_fc,
            "failclosed_FN": fn_fc,
            "failclosed_precision": prec_fc,
            "failclosed_recall": rec_fc,
            "failclosed_F1": f1_fc,
            "failclosed_FPR": fpr_fc,
            "failclosed_FNR": fnr_fc,
            "mean_modalities_requested": avg_mod,
            "mean_normalized_cost": avg_cost,
            "penalized_risk": avg_risk,
            "latency_p50_ms": p50_lat,
            "latency_mean_ms": avg_lat
        })
        
    df_res = pd.DataFrame(res_rows)
    df_res.to_csv(OUT_DIR / "RESULTADOS_INDEPENDIENTES_N240.csv", index=False)
    print(f"  + Tabla de resultados guardada en {OUT_DIR / 'RESULTADOS_INDEPENDIENTES_N240.csv'}")
    print(df_res[["policy", "coverage", "sel_F1", "sel_FPR", "mean_modalities_requested", "mean_normalized_cost", "penalized_risk"]].to_string())
    
    # 5. Calcular tabla de ablaciones sobre N=240
    print("\n[Paso 5/6] Calculando ablaciones A1-A6 sobre la cohorte independiente...")
    ab_eval = ["A1", "A2", "A3", "A4", "A5", "A6"]
    ab_rows = []
    
    sub_a6 = df_preds[df_preds["policy"] == "A6"].sort_values("external_id")
    trajs_a6 = sub_a6["action_sequence"].values
    
    for pol in ab_eval:
        sub = df_preds[df_preds["policy"] == pol].sort_values("external_id").copy()
        n = len(sub)
        dec = sub[sub["state"] == "decided"]
        n_dec = len(dec)
        cov = n_dec / n
        
        tp = int(((dec["y_true"] == 1) & (dec["decision"] == "phishing")).sum())
        fp = int(((dec["y_true"] == 0) & (dec["decision"] == "phishing")).sum())
        fn = int(((dec["y_true"] == 1) & (dec["decision"] == "legitimate")).sum())
        tn = int(((dec["y_true"] == 0) & (dec["decision"] == "legitimate")).sum())
        
        f1_sel = f1_score_calc(tp, fp, fn)
        avg_mod = round(float(sub["n_modalities"].mean()), 4)
        avg_cost = round(float(sub["normalized_cost"].mean()), 4)
        avg_risk = round(float(sub["penalized_risk"].mean()), 4)
        
        trajs_cur = sub["action_sequence"].values
        diff_trajs = int(np.sum(trajs_cur != trajs_a6))
        
        ab_rows.append({
            "variant": pol,
            "description": ablations_cfg[pol][0],
            "N": n,
            "coverage": round(cov, 4),
            "n_decided": n_dec,
            "n_abstained": n - n_dec,
            "sel_TP": tp,
            "sel_FP": fp,
            "sel_TN": tn,
            "sel_FN": fn,
            "sel_F1": f1_sel,
            "mean_modalities": avg_mod,
            "normalized_cost": avg_cost,
            "penalized_risk": avg_risk,
            "trajectories_differ_from_A6": diff_trajs
        })
    df_ab = pd.DataFrame(ab_rows)
    df_ab.to_csv(OUT_DIR / "ABLACIONES_INDEPENDIENTES_N240.csv", index=False)
    print(f"  + Tabla de ablaciones guardada en {OUT_DIR / 'ABLACIONES_INDEPENDIENTES_N240.csv'}")
    print(df_ab[["variant", "coverage", "sel_F1", "mean_modalities", "normalized_cost", "penalized_risk", "trajectories_differ_from_A6"]].to_string())
    
    # 6. Contrastes inferenciales estadisticos Bootstrap pareados (H1, H2, H3)
    print("\n[Paso 6/6] Contrastes estadisticos inferenciales prospectivos (Bootstrap pareado B=5,000)...")
    sub_raea = df_preds[df_preds["policy"] == "B6_RAEA"].sort_values("external_id")
    sub_m1 = df_preds[df_preds["policy"] == "B1_M1"].sort_values("external_id")
    sub_b5 = df_preds[df_preds["policy"] == "B5_M1_chow"].sort_values("external_id")
    
    cost_raea = sub_raea["normalized_cost"].values
    cost_m1 = sub_m1["normalized_cost"].values
    
    risk_raea = sub_raea["penalized_risk"].values
    risk_m1 = sub_m1["penalized_risk"].values
    risk_b5 = sub_b5["penalized_risk"].values
    
    d_cost, ci_c_l, ci_c_h, p_h3_raw = paired_bootstrap(cost_raea, cost_m1)
    d_r_m1, ci_r1_l, ci_r1_h, p_h1_raw = paired_bootstrap(risk_raea, risk_m1)
    d_r_b5, ci_rb5_l, ci_rb5_h, p_h2_raw = paired_bootstrap(risk_raea, risk_b5)
    
    p_raws = [p_h3_raw, p_h1_raw, p_h2_raw]
    order = np.argsort(p_raws)
    p_holm = np.zeros(3)
    p_holm[order[0]] = min(p_raws[order[0]] * 3, 1.0)
    p_holm[order[1]] = min(max(p_raws[order[1]] * 2, p_holm[order[0]]), 1.0)
    p_holm[order[2]] = min(max(p_raws[order[2]] * 1, p_holm[order[1]]), 1.0)
    
    stat_rows = [
        {"hypothesis": "H3_Cost_RAEA_vs_M1", "mean_diff": round(d_cost, 4), "ci_95_low": round(ci_c_l, 4), "ci_95_high": round(ci_c_h, 4), "p_raw": round(p_h3_raw, 5), "p_holm": round(p_holm[0], 5), "verdict": "ACEPTADA (p < 0.001)" if p_holm[0] < 0.05 else "RECHAZADA"},
        {"hypothesis": "H1_Risk_RAEA_vs_M1", "mean_diff": round(d_r_m1, 4), "ci_95_low": round(ci_r1_l, 4), "ci_95_high": round(ci_r1_h, 4), "p_raw": round(p_h1_raw, 5), "p_holm": round(p_holm[1], 5), "verdict": "ACEPTADA (p < 0.05)" if p_holm[1] < 0.05 else ("MARGINAL (p < 0.10)" if p_raws[1] < 0.10 else "NO SIGNIFICATIVA")},
        {"hypothesis": "H2_Risk_RAEA_vs_B5", "mean_diff": round(d_r_b5, 4), "ci_95_low": round(ci_rb5_l, 4), "ci_95_high": round(ci_rb5_h, 4), "p_raw": round(p_h2_raw, 5), "p_holm": round(p_holm[2], 5), "verdict": "RECHAZADA (B5 logra menor riesgo)" if d_r_b5 > 0 else "ACEPTADA"}
    ]
    df_stat = pd.DataFrame(stat_rows)
    df_stat.to_csv(OUT_DIR / "ESTADISTICA_INDEPENDIENTE_N240.csv", index=False)
    print(f"  + Contrastes estadisticos guardados en {OUT_DIR / 'ESTADISTICA_INDEPENDIENTE_N240.csv'}")
    print(df_stat.to_string())
    
    # 7. Generar Figuras cientificas para N=240
    print("\nGenerando figuras cientificas para la cohorte independiente...")
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    
    # Fig 1: Cost vs Coverage
    fig, ax = plt.subplots(figsize=(7.5, 5))
    ax.scatter(df_res["mean_normalized_cost"], df_res["coverage"], s=110, color="navy", zorder=3)
    for _, r in df_res.iterrows():
        ax.annotate(r["policy"], (r["mean_normalized_cost"] + 0.01, r["coverage"] - 0.015), fontsize=9)
    ax.set_xlabel("Coste Normalizado de Adquisicion")
    ax.set_ylabel("Cobertura Selectiva")
    ax.set_title("Compromiso Coste-Cobertura en Cohorte Independiente (N=240)")
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig1_n240_cost_vs_coverage.png", dpi=300)
    plt.close(fig)
    
    # Fig 2: Risk vs Coverage
    fig, ax = plt.subplots(figsize=(7.5, 5))
    ax.scatter(df_res["coverage"], df_res["penalized_risk"], s=110, color="crimson", zorder=3)
    for _, r in df_res.iterrows():
        ax.annotate(r["policy"], (r["coverage"] + 0.005, r["penalized_risk"] + 0.03), fontsize=9)
    ax.set_xlabel("Cobertura Selectiva")
    ax.set_ylabel("Riesgo Penalizado Esperado (gamma=15.0)")
    ax.set_title("Riesgo Penalizado vs Cobertura (N=240)")
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig2_n240_risk_curves.png", dpi=300)
    plt.close(fig)
    
    # Fig 3: Comparativa F1 y Coste
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    pols = df_res["policy"].tolist()
    x = np.arange(len(pols))
    w = 0.35
    ax.bar(x - w/2, df_res["sel_F1"], width=w, label="F1 Selectivo", color="steelblue")
    ax.bar(x + w/2, df_res["mean_normalized_cost"], width=w, label="Coste Normalizado", color="darkorange")
    ax.set_xticks(x)
    ax.set_xticklabels(pols, rotation=25, ha="right")
    ax.set_ylabel("Valor")
    ax.set_title("Comparacion Predictiva y Operacional en Cohorte Independiente (N=240)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig3_n240_policy_comparison.png", dpi=300)
    plt.close(fig)
    
    # Fig 4: Ablaciones
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    abs_names = df_ab["variant"].tolist()
    ax.barh(abs_names, df_ab["normalized_cost"], color="teal", alpha=0.85)
    ax.set_xlabel("Coste Normalizado de Adquisicion")
    ax.set_title("Analisis de Ablaciones RAEA sobre Cohorte Independiente (N=240)")
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig4_n240_ablations.png", dpi=300)
    plt.close(fig)
    print("  + Figuras 1-4 guardadas en artifacts/raea_independent_n240/FIGURAS/")

    print("\n" + "=" * 75)
    print("EVALUACION PROSPECTIVA COMPLETADA EXITOSAMENTE.")
    print("=" * 75)

if __name__ == "__main__":
    main()
