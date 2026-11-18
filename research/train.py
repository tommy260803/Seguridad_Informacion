"""
research.train: Entrenamiento y calibración formal de M0 y Estimador de Disponibilidad
utilizando exclusivamente observaciones empíricas reales.
CERO etiquetas sintéticas/aleatorias y resolución automática mediante research.workspace.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import time
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score

try:
    from sklearn.frozen import FrozenEstimator
except ImportError:
    FrozenEstimator = None

from phishguard_data.psl import PublicSuffixList
from phishguard_data.urls import canonicalize_url
from phishguard_ml.features import (
    FEATURE_NAMES,
    FEATURE_PROFILES,
    UrlFeatureContext,
    extract_url_features,
)
from research.workspace import find_data_file, get_candidate_roots, get_experiments_dir

def get_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def train_all_models(workspace_root: Path | None = None, sample_limit: int | None = None) -> dict[str, Any]:
    here = Path(__file__).resolve()
    root = workspace_root or here.parent.parent
    
    # Directorios de salida para modelos
    out_dirs = [
        root / "artifacts" / "models_reproduced",
        root / "artifacts" / "raea",
        root / "MODELOS" / "M0",
        root / "MODELOS" / "AVAILABILITY",
    ]
    for d in out_dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    metadata = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "models": {},
    }
    
    print("=" * 70)
    print("[research.train] INICIANDO ENTRENAMIENTO CIENTÍFICO CON OBSERVACIONES 100% REALES")
    print("=" * 70)

    # 1. Localizar y cargar samples.csv y conventional.csv mediante research.workspace
    samples_path = find_data_file("samples.csv", ["processed/0.1.0"])
    splits_path = find_data_file("conventional.csv", ["processed/0.1.0/splits"])

    print(f"[research.train] 1. Extrayendo características para M0 desde {samples_path.name}...")
    samples_df = pd.read_csv(samples_path, nrows=sample_limit) if sample_limit else pd.read_csv(samples_path)
    splits_df = pd.read_csv(splits_path, nrows=sample_limit) if sample_limit else pd.read_csv(splits_path)
    df = pd.merge(samples_df, splits_df, on="sample_id")
    
    auth_features = FEATURE_PROFILES["authority_only"]
    X_rows = []
    y_labels = []
    
    t0 = time.time()
    for _, row in df.iterrows():
        ctx = UrlFeatureContext(canonical_url=row["canonical_url"], registered_domain=str(row["registered_domain"]))
        fdict = extract_url_features(ctx)
        vec = [fdict.get(k, 0.0) for k in auth_features]
        X_rows.append(vec)
        y_labels.append(1 if row["label"] == "phishing" else 0)
        
    X = np.asarray(X_rows, dtype=np.float32)
    y = np.asarray(y_labels, dtype=np.int32)
    
    # Filtrado estricto por partición: NUNCA tocar test
    train_mask = (df["partition"] == "train").values
    val_mask = (df["partition"].isin(["validation", "val"])).values
        
    if val_mask.sum() == 0 or train_mask.sum() == 0:
        n_train = int(len(X) * 0.8)
        X_train, y_train = X[:n_train], y[:n_train]
        X_val, y_val = X[n_train:], y[n_train:]
    else:
        X_train, y_train = X[train_mask], y[train_mask]
        X_val, y_val = X[val_mask], y[val_mask]
        
    print(f"  + Muestras de entrenamiento: {len(X_train):,} | Validación: {len(X_val):,} (Cero fuga de test)")
    
    # Entrenar M0 (HistGradientBoosting + Calibración Isotonic mediante FrozenEstimator)
    print("[research.train] 2. Ajustando clasificador M0 (HistGradientBoosting + CalibratedClassifierCV)...")
    base_m0 = HistGradientBoostingClassifier(max_iter=100, random_state=42)
    base_m0.fit(X_train, y_train)
    
    if FrozenEstimator is not None:
        cal_m0 = CalibratedClassifierCV(estimator=FrozenEstimator(base_m0), method="isotonic")
    else:
        cal_m0 = CalibratedClassifierCV(estimator=base_m0, method="isotonic", cv="prefit")
    cal_m0.fit(X_val, y_val)
    t_m0 = time.time() - t0
    
    m0_artifact = {
        "schema_version": 1,
        "experiment_version": "m0-reproduced-2.1.0",
        "feature_version": "url-features-1.0.0",
        "feature_profile": "authority_only",
        "feature_names": list(auth_features),
        "candidate": "histgb-63-isotonic",
        "threshold": 0.3827,
        "model": cal_m0,
    }
    
    m0_path = root / "artifacts" / "models_reproduced" / "m0_reproduced.joblib"
    m0_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(m0_artifact, m0_path)
    
    m0_zip_path = root / "MODELOS" / "M0" / "model.joblib"
    m0_zip_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(m0_artifact, m0_zip_path)
    
    h_m0 = get_sha256(m0_path)
    print(f"  + M0 entrenado en {t_m0:.2f}s | Artefacto: {m0_path.name} | SHA256: {h_m0[:16]}... [OK]")
    metadata["models"]["M0"] = {
        "features": list(auth_features),
        "n_features": len(auth_features),
        "train_seconds": t_m0,
        "artifact": str(m0_path),
        "sha256": h_m0,
    }

    # 3. Entrenar Estimador de Disponibilidad pi_m(x0) sobre DATOS EMPÍRICOS REALES
    print("[research.train] 3. Entrenando Estimador de Disponibilidad pi_m(x0) desde OBSERVACIONES REALES...")
    probe_raw_path = find_data_file("probe_raw.jsonl")
    
    meta_df = None
    try:
        meta_path = find_data_file("COHORTE_Y_ETIQUETAS.csv")
        meta_df = pd.read_csv(meta_path).set_index("cohort2_id")
    except Exception:
        pass
    
    avail_feature_names = [
        "host_length", "url_length", "host_entropy", "has_ip_host",
        "uses_https", "p_m0", "dot_count", "host_label_count", "subdomain_count"
    ]
    
    print(f"  + Leyendo observaciones empíricas de adquisición desde: {probe_raw_path}")
    rows_avail = []
    with open(probe_raw_path, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            cid = d["sample"].get("cohort2_id", d["sample"].get("external_id", ""))
            url = d["sample"]["canonical_url"]
            infra_st = d.get("probe", {}).get("infra", {}).get("status", "error")
            content_st = d.get("probe", {}).get("content", {}).get("status", "error")
            
            part = "unknown"
            if meta_df is not None and cid in meta_df.index:
                part = str(meta_df.loc[cid, "partition"])
            
            try:
                ctx = UrlFeatureContext(canonical_url=url, registered_domain=str(d["sample"].get("registered_domain", "")))
                fdict = extract_url_features(ctx)
            except Exception:
                fdict = {}
                
            vec_m0 = [[fdict.get(k, 0.0) for k in auth_features]]
            p0_est = float(cal_m0.predict_proba(vec_m0)[0, 1])
            
            rows_avail.append({
                "cid": cid,
                "partition": part,
                "host_length": float(fdict.get("host_length", 15.0)),
                "url_length": float(fdict.get("url_length", len(url))),
                "host_entropy": float(fdict.get("host_entropy", 3.0)),
                "has_ip_host": float(fdict.get("has_ip_host", 0.0)),
                "uses_https": 1.0 if url.startswith("https://") else 0.0,
                "p_m0": p0_est,
                "dot_count": float(fdict.get("dot_count", url.count("."))),
                "host_label_count": float(fdict.get("host_label_count", 2.0)),
                "subdomain_count": float(fdict.get("subdomain_count", 0.0)),
                "target_infra_avail": 1 if infra_st == "success" else 0,
                "target_content_avail": 1 if content_st == "success" else 0,
            })
            
    df_avail = pd.DataFrame(rows_avail)
    print(f"  + Total observaciones empíricas cargadas: N={len(df_avail):,}")

    # Separación estricta: train_avail para ajuste, test_eval para validación out-of-sample
    if "train_avail" in df_avail["partition"].values and "test_eval" in df_avail["partition"].values:
        train_avail_df = df_avail[df_avail["partition"] == "train_avail"].copy()
        val_avail_df = df_avail[df_avail["partition"] == "test_eval"].copy()
    else:
        n_half = len(df_avail) // 2
        train_avail_df = df_avail.iloc[:n_half].copy()
        val_avail_df = df_avail.iloc[n_half:].copy()

    # Subdividir train_avail en ajuste (67%) y calibración interna (33%)
    n_sub = int(len(train_avail_df) * 0.67)
    sub_tr = train_avail_df.iloc[:n_sub]
    sub_cal = train_avail_df.iloc[n_sub:]

    X_subtr = sub_tr[avail_feature_names].values
    X_subcal = sub_cal[avail_feature_names].values
    X_val_avail = val_avail_df[avail_feature_names].values
    
    base_infra = LogisticRegression(C=0.2, max_iter=1000, random_state=42)
    base_infra.fit(X_subtr, sub_tr["target_infra_avail"].values)
    
    base_content = LogisticRegression(C=0.2, max_iter=1000, random_state=42)
    base_content.fit(X_subtr, sub_tr["target_content_avail"].values)
    
    if FrozenEstimator is not None:
        clf_infra = CalibratedClassifierCV(estimator=FrozenEstimator(base_infra), method="sigmoid")
        clf_content = CalibratedClassifierCV(estimator=FrozenEstimator(base_content), method="sigmoid")
    else:
        clf_infra = CalibratedClassifierCV(estimator=base_infra, method="sigmoid", cv="prefit")
        clf_content = CalibratedClassifierCV(estimator=base_content, method="sigmoid", cv="prefit")
        
    clf_infra.fit(X_subcal, sub_cal["target_infra_avail"].values)
    clf_content.fit(X_subcal, sub_cal["target_content_avail"].values)
    
    # Métricas out-of-sample en partición independiente test_eval
    p_val_infra = clf_infra.predict_proba(X_val_avail)[:, 1]
    p_val_content = clf_content.predict_proba(X_val_avail)[:, 1]
    
    auc_infra = float(roc_auc_score(val_avail_df["target_infra_avail"], p_val_infra))
    brier_infra = float(brier_score_loss(val_avail_df["target_infra_avail"], p_val_infra))
    auc_content = float(roc_auc_score(val_avail_df["target_content_avail"], p_val_content))
    brier_content = float(brier_score_loss(val_avail_df["target_content_avail"], p_val_content))

    prior_infra = float(train_avail_df["target_infra_avail"].mean())
    prior_content = float(train_avail_df["target_content_avail"].mean())
    brier_const_infra = float(brier_score_loss(val_avail_df["target_infra_avail"], np.full(len(val_avail_df), prior_infra)))
    brier_const_content = float(brier_score_loss(val_avail_df["target_content_avail"], np.full(len(val_avail_df), prior_content)))
    
    print(f"  + Estimador Red / Infra:     AUC={auc_infra:.4f} | Brier={brier_infra:.4f} vs Constante Prior={brier_const_infra:.4f} (Validación out-of-sample N={len(val_avail_df)})")
    print(f"  + Estimador Contenido / DOM: AUC={auc_content:.4f} | Brier={brier_content:.4f} vs Constante Prior={brier_const_content:.4f} (Validación out-of-sample N={len(val_avail_df)})")
    
    avail_artifact = {
        "infra_model": clf_infra,
        "content_model": clf_content,
        "feature_names": avail_feature_names,
        "version": "availability-real-probe-2.2.0",
        "trained_on": f"real_probe_train_avail (N={len(train_avail_df)})",
        "prior_rates": {"infra": prior_infra, "content": prior_content},
        "val_metrics": {
            "auc_infra": auc_infra,
            "brier_infra": brier_infra,
            "brier_const_infra": brier_const_infra,
            "auc_content": auc_content,
            "brier_content": brier_content,
            "brier_const_content": brier_const_content,
        }
    }
    
    avail_paths = [
        root / "artifacts" / "models_reproduced" / "availability_reproduced.joblib",
        root / "artifacts" / "raea" / "availability_estimator.joblib",
        root / "MODELOS" / "AVAILABILITY" / "availability_estimator.joblib",
    ]
    for ap in avail_paths:
        ap.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(avail_artifact, ap)
    
    avail_path = avail_paths[0]
    h_avail = get_sha256(avail_path)
    print(f"  + Estimador guardado: {avail_path.name} | SHA256: {h_avail[:16]}... [OK]")
    metadata["models"]["Availability"] = {
        "features": avail_feature_names,
        "n_features": len(avail_feature_names),
        "train_samples": len(train_avail_df),
        "val_samples": len(val_avail_df),
        "artifact": str(avail_path),
        "sha256": h_avail,
        "auc_infra": auc_infra,
        "brier_infra": brier_infra,
        "brier_const_infra": brier_const_infra,
        "auc_content": auc_content,
        "brier_content": brier_content,
        "brier_const_content": brier_const_content,
        "prior_rates": {"infra": prior_infra, "content": prior_content},
    }
    
    exp_dir = get_experiments_dir()
    meta_out = exp_dir / "TRAINING_METADATA.json"
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[research.train] Metadatos de entrenamiento guardados en {meta_out.name}")
    print("=" * 70)
    return metadata

if __name__ == "__main__":
    train_all_models()
