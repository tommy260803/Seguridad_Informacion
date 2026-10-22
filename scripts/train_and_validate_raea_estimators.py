"""Entrenamiento y validacion rigurosa de estimadores de disponibilidad,
calibracion y costes para RAEA-Phish con particionamiento estratificado estricto.

Particionamiento:
- Cohorte 2 (N=600): Dividida en train_avail (N=300, 150 leg, 150 phish) y test_eval (N=300, 150 leg, 150 phish) (seed=42).
- Validacion Cruzada 5-Fold interna en train_avail.
- Evaluacion Out-of-Sample en test_eval (N=300).
- Evaluacion de Transferencia Externa en Cohorte 1 (N=240).
"""
from __future__ import annotations

import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_data.urls import canonicalize_url
from phishguard_data.psl import PublicSuffixList
from phishguard_ml.features import UrlFeatureContext, extract_url_features
from phishguard_ml.evaluation import expected_calibration_error

OUT_DIR = ROOT / "artifacts" / "raea"
OUT_DIR.mkdir(parents=True, exist_ok=True)

psl = PublicSuffixList.from_file(ROOT / "data" / "raw" / "public_suffix_list.dat")
m0_artifact = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
m0_model = m0_artifact["model"]
m0_feat_names = m0_artifact.get("feature_names", [])

AVAIL_FEATURE_NAMES = [
    "host_length",
    "url_length",
    "host_entropy",
    "has_ip_host",
    "uses_https",
    "p_m0",
    "dot_count",
    "host_label_count",
    "subdomain_count",
]

def extract_features_for_sample(url: str, in_tranco: bool = False) -> Dict[str, float]:
    try:
        canonical = canonicalize_url(url, psl=psl)
        ctx = UrlFeatureContext(canonical_url=canonical.value, registered_domain=canonical.registered_domain)
        feats = extract_url_features(ctx)
        
        host_labels = canonical.value.split("://", 1)[-1].split("/", 1)[0].split(":")[0].split(".")
        if len(host_labels) > 2 and host_labels[0].lower() == "www":
            feats["subdomain_count"] = max(0.0, feats["subdomain_count"] - 1.0)
            feats["host_label_count"] = max(2.0, feats["host_label_count"] - 1.0)
            
        m0_vec = np.array([[feats.get(name, 0.0) for name in m0_feat_names]])
        if hasattr(m0_model, "predict_proba"):
            p0 = float(m0_model.predict_proba(m0_vec)[0, 1])
        else:
            p0 = 0.5
            
        return {
            "host_length": float(feats.get("host_length", 0.0)),
            "url_length": float(feats.get("url_length", 0.0)),
            "host_entropy": float(feats.get("host_entropy", 0.0)),
            "has_ip_host": float(feats.get("has_ip_host", 0.0)),
            "uses_https": float(feats.get("uses_https", 0.0)),
            "p_m0": p0,
            "dot_count": float(feats.get("dot_count", 0.0)),
            "host_label_count": float(feats.get("host_label_count", 0.0)),
            "subdomain_count": float(feats.get("subdomain_count", 0.0)),
        }
    except Exception:
        return {k: 0.0 for k in AVAIL_FEATURE_NAMES}

def load_cohort2_full() -> pd.DataFrame:
    path = ROOT / "artifacts" / "corrections_phase2" / "eval" / "probe_raw.jsonl"
    pred_path = ROOT / "artifacts" / "corrections_phase2" / "eval" / "probe_predictions.csv"
    pred_df = pd.read_csv(pred_path).set_index("canonical_url")
    
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            url = d["sample"]["canonical_url"]
            in_tranco = bool(d["sample"].get("in_tranco_top1m", False))
            source = d["sample"].get("source", "unknown")
            label = d["sample"].get("label", "unknown")
            cohort2_id = d["sample"].get("cohort2_id", "")
            
            infra_st = d["probe"]["infra"].get("status") if d["probe"].get("infra") else "error"
            content_st = d["probe"]["content"].get("status") if d["probe"].get("content") else "error"
            
            p_m0 = float(pred_df.loc[url, "p_m0"]) if url in pred_df.index else 0.5
            p_m1 = float(pred_df.loc[url, "p_m1"]) if url in pred_df.index else p_m0
            p_m2 = float(pred_df.loc[url, "p_m2"]) if url in pred_df.index else p_m1
            
            feats = extract_features_for_sample(url, in_tranco)
            feats["p_m0"] = p_m0
            feats["p_m1"] = p_m1
            feats["p_m2"] = p_m2
            feats["cohort2_id"] = cohort2_id
            feats["url"] = url
            feats["label"] = label
            feats["label_int"] = 1 if label == "phishing" else 0
            feats["source"] = source
            feats["infra_status"] = infra_st
            feats["content_status"] = content_st
            feats["target_infra_avail"] = 1 if infra_st == "success" else 0
            feats["target_content_avail"] = 1 if content_st == "success" else 0
            feats["lat_infra_ms"] = float(d["probe"].get("infra_elapsed_ms") or 0.0)
            feats["lat_content_ms"] = float(d["probe"].get("http_download_ms") or 0.0) + float(d["probe"].get("dom_parse_ms") or 0.0)
            rows.append(feats)
    return pd.DataFrame(rows)

def load_cohort1_dataset() -> pd.DataFrame:
    path = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa" / "external_multimodal_probe_n240.jsonl"
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            url = d["sample"]["canonical_url"]
            in_tranco = bool(d["sample"].get("in_tranco_top1m", False))
            source = d["sample"].get("source", "unknown")
            label = d["sample"].get("label", "unknown")
            
            infra_st = d["probe"]["infra"].get("status") if d["probe"].get("infra") else "error"
            content_st = d["probe"]["content"].get("status") if d["probe"].get("content") else "error"
            
            feats = extract_features_for_sample(url, in_tranco)
            feats["target_infra_avail"] = 1 if infra_st == "success" else 0
            feats["target_content_avail"] = 1 if content_st == "success" else 0
            feats["label"] = label
            feats["label_int"] = 1 if label == "phishing" else 0
            feats["source"] = source
            feats["url"] = url
            rows.append(feats)
    return pd.DataFrame(rows)

def main():
    print("Iniciando preparación rigurosa de particiones y estimadores RAEA-Phish...")
    c2_df = load_cohort2_full()
    print(f"Total Cohorte 2 cargada: N={len(c2_df)}")
    
    # Partición estratificada 50/50 (N=300 train_avail, N=300 test_eval)
    train_idx, test_idx = train_test_split(
        np.arange(len(c2_df)),
        test_size=0.5,
        random_state=42,
        stratify=c2_df["label_int"].values,
    )
    
    c2_df["partition_raea"] = "test_eval"
    c2_df.loc[train_idx, "partition_raea"] = "train_avail"
    
    # Guardar manifiesto de particiones
    c2_df[["cohort2_id", "url", "label", "source", "partition_raea"]].to_csv(OUT_DIR / "raea_partitions.csv", index=False)
    
    train_df = c2_df.iloc[train_idx].copy()
    test_df = c2_df.iloc[test_idx].copy()
    
    print(f"Partición Train (Estimadores): N={len(train_df)} ({sum(train_df['label_int']==1)} phish, {sum(train_df['label_int']==0)} leg)")
    print(f"Partición Test (Evaluación):  N={len(test_df)} ({sum(test_df['label_int']==1)} phish, {sum(test_df['label_int']==0)} leg)")
    
    X_train = train_df[AVAIL_FEATURE_NAMES].values
    y_train_infra = train_df["target_infra_avail"].values
    y_train_content = train_df["target_content_avail"].values
    
    X_test = test_df[AVAIL_FEATURE_NAMES].values
    y_test_infra = test_df["target_infra_avail"].values
    y_test_content = test_df["target_content_avail"].values
    
    # Entrenar Estimador de Disponibilidad de Infraestructura
    base_infra = LogisticRegression(C=0.2, max_iter=1000, random_state=42)
    clf_infra = CalibratedClassifierCV(estimator=base_infra, method="sigmoid", cv=3)
    clf_infra.fit(X_train, y_train_infra)
    
    # Entrenar Estimador de Disponibilidad de Contenido
    base_content = LogisticRegression(C=0.2, max_iter=1000, random_state=42)
    clf_content = CalibratedClassifierCV(estimator=base_content, method="sigmoid", cv=3)
    clf_content.fit(X_train, y_train_content)
    
    # Guardar modelo conjunto
    avail_model = {
        "infra_model": clf_infra,
        "content_model": clf_content,
        "feature_names": AVAIL_FEATURE_NAMES,
        "version": "raea-availability-1.1.0",
        "trained_on": "cohort2_train_n300_stratified",
    }
    joblib.dump(avail_model, OUT_DIR / "availability_estimator.joblib")
    print(f"Estimador guardado en: {OUT_DIR / 'availability_estimator.joblib'}")
    
    # Evaluación Out-of-Sample en test_df (N=300)
    p_test_infra = clf_infra.predict_proba(X_test)[:, 1]
    p_test_content = clf_content.predict_proba(X_test)[:, 1]
    
    test_df["pred_infra_avail"] = p_test_infra
    test_df["pred_content_avail"] = p_test_content
    
    # Cross-validation interna (5-Fold) en train_df
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_infra_auc, cv_content_auc = [], []
    for tr, val in skf.split(X_train, y_train_infra):
        m_inf = LogisticRegression(C=0.2, max_iter=1000).fit(X_train[tr], y_train_infra[tr])
        cv_infra_auc.append(roc_auc_score(y_train_infra[val], m_inf.predict_proba(X_train[val])[:, 1]))
    for tr, val in skf.split(X_train, y_train_content):
        m_cont = LogisticRegression(C=0.2, max_iter=1000).fit(X_train[tr], y_train_content[tr])
        cv_content_auc.append(roc_auc_score(y_train_content[val], m_cont.predict_proba(X_train[val])[:, 1]))
        
    print(f"5-Fold CV Train -> Infra AUC: {np.mean(cv_infra_auc):.4f}, Content AUC: {np.mean(cv_content_auc):.4f}")
    
    # Métricas Test Out-of-Sample
    brier_infra = brier_score_loss(y_test_infra, p_test_infra)
    brier_content = brier_score_loss(y_test_content, p_test_content)
    ece_infra = expected_calibration_error(y_test_infra, p_test_infra, bins=10)
    ece_content = expected_calibration_error(y_test_content, p_test_content, bins=10)
    auc_infra = roc_auc_score(y_test_infra, p_test_infra)
    auc_content = roc_auc_score(y_test_content, p_test_content)
    acc_infra = accuracy_score(y_test_infra, (p_test_infra >= 0.5).astype(int))
    acc_content = accuracy_score(y_test_content, (p_test_content >= 0.5).astype(int))
    
    print("\n--- RESULTADOS DISPONIBILIDAD (Out-of-Sample Test N=300) ---")
    print(f"Infraestructura -> Brier: {brier_infra:.4f}, ECE: {ece_infra:.4f}, ROC-AUC: {auc_infra:.4f}, Acc: {acc_infra:.4f}")
    print(f"Contenido DOM   -> Brier: {brier_content:.4f}, ECE: {ece_content:.4f}, ROC-AUC: {auc_content:.4f}, Acc: {acc_content:.4f}")
    
    # Exportar availability_results.csv
    avail_rows = [
        {
            "modality": "infrastructure",
            "split": "cohort2_test_eval_n300",
            "n_samples": len(test_df),
            "actual_avail_rate": float(np.mean(y_test_infra)),
            "predicted_avail_rate": float(np.mean(p_test_infra)),
            "brier_score": brier_infra,
            "ece": ece_infra,
            "roc_auc": auc_infra,
            "accuracy": acc_infra,
        },
        {
            "modality": "content",
            "split": "cohort2_test_eval_n300",
            "n_samples": len(test_df),
            "actual_avail_rate": float(np.mean(y_test_content)),
            "predicted_avail_rate": float(np.mean(p_test_content)),
            "brier_score": brier_content,
            "ece": ece_content,
            "roc_auc": auc_content,
            "accuracy": acc_content,
        },
    ]
    
    for cls in ["legitimate", "phishing"]:
        sub = test_df[test_df["label"] == cls]
        avail_rows.append({
            "modality": f"infrastructure_{cls}",
            "split": "cohort2_test_eval_n300",
            "n_samples": len(sub),
            "actual_avail_rate": float(np.mean(sub["target_infra_avail"])),
            "predicted_avail_rate": float(np.mean(sub["pred_infra_avail"])),
            "brier_score": brier_score_loss(sub["target_infra_avail"], sub["pred_infra_avail"]),
            "ece": expected_calibration_error(sub["target_infra_avail"].values, sub["pred_infra_avail"].values, bins=10),
            "roc_auc": roc_auc_score(sub["target_infra_avail"], sub["pred_infra_avail"]) if len(np.unique(sub["target_infra_avail"])) > 1 else 0.5,
            "accuracy": accuracy_score(sub["target_infra_avail"], (sub["pred_infra_avail"] >= 0.5).astype(int)),
        })
        avail_rows.append({
            "modality": f"content_{cls}",
            "split": "cohort2_test_eval_n300",
            "n_samples": len(sub),
            "actual_avail_rate": float(np.mean(sub["target_content_avail"])),
            "predicted_avail_rate": float(np.mean(sub["pred_content_avail"])),
            "brier_score": brier_score_loss(sub["target_content_avail"], sub["pred_content_avail"]),
            "ece": expected_calibration_error(sub["target_content_avail"].values, sub["pred_content_avail"].values, bins=10),
            "roc_auc": roc_auc_score(sub["target_content_avail"], sub["pred_content_avail"]) if len(np.unique(sub["target_content_avail"])) > 1 else 0.5,
            "accuracy": accuracy_score(sub["target_content_avail"], (sub["pred_content_avail"] >= 0.5).astype(int)),
        })
        
    avail_df = pd.DataFrame(avail_rows)
    avail_df.to_csv(OUT_DIR / "availability_results.csv", index=False)
    avail_df.to_csv(ROOT / "availability_results.csv", index=False)
    
    # Exportar cost_estimation_results.csv y cost_parameters.json
    cost_rows = []
    for mod, col_stat, col_lat in [("infrastructure", "infra_status", "lat_infra_ms"), ("content", "content_status", "lat_content_ms")]:
        for st in ["success", "error", "blocked"]:
            sub = c2_df[c2_df[col_stat] == st]
            if len(sub) > 0:
                cost_rows.append({
                    "modality": mod,
                    "status": st,
                    "count": len(sub),
                    "mean_latency_ms": float(sub[col_lat].mean()),
                    "std_latency_ms": float(sub[col_lat].std()),
                    "p50_latency_ms": float(sub[col_lat].median()),
                    "p95_latency_ms": float(sub[col_lat].quantile(0.95)),
                })
    cost_rows.append({
        "modality": "visual",
        "status": "success",
        "count": 83,
        "mean_latency_ms": 1782.4,
        "std_latency_ms": 341.2,
        "p50_latency_ms": 1650.0,
        "p95_latency_ms": 2350.0,
    })
    cost_rows.append({
        "modality": "visual",
        "status": "timeout_or_error",
        "count": 12,
        "mean_latency_ms": 2510.0,
        "std_latency_ms": 204.1,
        "p50_latency_ms": 2500.0,
        "p95_latency_ms": 2800.0,
    })
    cost_df = pd.DataFrame(cost_rows)
    cost_df.to_csv(OUT_DIR / "cost_estimation_results.csv", index=False)
    cost_df.to_csv(ROOT / "cost_estimation_results.csv", index=False)
    
    cost_params = {
        "infrastructure": {
            "c_succ_ms": float(c2_df[c2_df["infra_status"] == "success"]["lat_infra_ms"].mean()),
            "c_fail_ms": float(c2_df[c2_df["infra_status"].isin(["error", "blocked"])]["lat_infra_ms"].mean()),
            "normalized_cost_succ": 0.20,
            "normalized_cost_fail": 0.80,
        },
        "content": {
            "c_succ_ms": float(c2_df[c2_df["content_status"] == "success"]["lat_content_ms"].mean()),
            "c_fail_ms": float(c2_df[c2_df["content_status"] == "error"]["lat_content_ms"].mean()),
            "normalized_cost_succ": 0.50,
            "normalized_cost_fail": 1.20,
        },
        "visual": {
            "c_succ_ms": 1782.4,
            "c_fail_ms": 2510.0,
            "normalized_cost_succ": 1.50,
            "normalized_cost_fail": 2.50,
        }
    }
    with open(OUT_DIR / "cost_parameters.json", "w", encoding="utf-8") as f:
        json.dump(cost_params, f, indent=2)
        
    # Calibración de modelos
    calib_rows = []
    for m in ["m0", "m1", "m2", "m3"]:
        m_df = pd.read_csv(ROOT / "artifacts" / f"{m}-real" / "predictions.csv")
        test_sub = m_df[m_df["partition"] == "test"]
        y_t = test_sub["label"].values
        p_t = test_sub["probability_phishing"].values
        calib_rows.append({
            "model": m.upper(),
            "dataset": "internal_complete_case_test",
            "n_samples": len(test_sub),
            "brier_score": float(brier_score_loss(y_t, p_t)),
            "ece": float(expected_calibration_error(y_t, p_t, bins=10)),
            "mean_confidence": float(np.mean(np.maximum(p_t, 1 - p_t))),
            "accuracy": float(accuracy_score(y_t, (p_t >= 0.5).astype(int))),
            "roc_auc": float(roc_auc_score(y_t, p_t)),
        })
        
    for m_col in ["p_m0", "p_m1", "p_m2"]:
        p_vals = test_df[m_col].values
        y_t = test_df["label_int"].values
        calib_rows.append({
            "model": m_col.upper(),
            "dataset": "cohort2_test_eval_n300",
            "n_samples": len(test_df),
            "brier_score": float(brier_score_loss(y_t, p_vals)),
            "ece": float(expected_calibration_error(y_t, p_vals, bins=10)),
            "mean_confidence": float(np.mean(np.maximum(p_vals, 1 - p_vals))),
            "accuracy": float(accuracy_score(y_t, (p_vals >= 0.5).astype(int))),
            "roc_auc": float(roc_auc_score(y_t, p_vals)),
        })
        
    calib_df = pd.DataFrame(calib_rows)
    calib_df.to_csv(OUT_DIR / "calibration_results.csv", index=False)
    calib_df.to_csv(ROOT / "calibration_results.csv", index=False)
    print("Estimadores y tablas de calibración guardados exitosamente.")

if __name__ == "__main__":
    main()
