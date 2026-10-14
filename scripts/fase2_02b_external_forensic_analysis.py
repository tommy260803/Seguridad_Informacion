#!/usr/bin/env python3
"""
Forensic analysis of external dataset shift in M0, M1, M2, and M4:
1. Per-source breakdown on the Complete-Case multimodal subset (N_CC = 104).
2. Controlled ablation of `www.` canonicalization (comparing raw URL vs `www.`-stripped URL,
   matching `HybridM0Model` in `src/phishguard_api/inference.py` lines 68-70) on:
   - Full external cohort N = 1,054 (M0 variants)
   - Complete-Case external cohort N_CC = 104 (M0, M1, M2, M4)
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.content import CONTENT_FEATURE_NAMES, extract_content_features
from phishguard_ml.features import AUTHORITY_FEATURE_NAMES, UrlFeatureContext, extract_url_features
from phishguard_ml.infrastructure import INFRA_FEATURE_NAMES, extract_infrastructure_features

OUT_DIR = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa"


def strip_www(url: str) -> str:
    if url.startswith("http://www."):
        return "http://" + url[11:]
    if url.startswith("https://www."):
        return "https://" + url[12:]
    return url


def extract_m0_vec(url: str, reg_domain: str, normalize_www: bool = False) -> np.ndarray:
    u = strip_www(url) if normalize_www else url
    ctx = UrlFeatureContext(canonical_url=u, registered_domain=reg_domain)
    feats = extract_url_features(ctx)
    return np.array([float(feats[k]) for k in AUTHORITY_FEATURE_NAMES], dtype=np.float64)


def compute_basic_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, Any]:
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

    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    return {
        "n": int(len(y_true)),
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
        "brier": round(float(brier_score_loss(y_true, y_prob)), 6),
    }


def main() -> None:
    ext_rows = list(csv.DictReader((OUT_DIR / "external_validation_dataset_n1200.csv").open("r", encoding="utf-8")))
    m0_full_b = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    m0_cc_b = joblib.load(ROOT / "artifacts" / "m0-real" / "model.joblib")
    m1_cc_b = joblib.load(ROOT / "artifacts" / "m1-real" / "model.joblib")
    m2_cc_b = joblib.load(ROOT / "artifacts" / "m2-real" / "model.joblib")

    thr_m0 = 0.43393651111753984
    thr_m0_cc = 0.38266699053469533
    thr_m1_cc = 0.5250141792140176
    thr_m2_cc = 0.39496177581001815

    y_all = np.array([1 if str(r.get("label_int", r["label"])) in ("1", "phishing") else 0 for r in ext_rows], dtype=int)
    X_raw = np.vstack([extract_m0_vec(r["canonical_url"], r["registered_domain"], False) for r in ext_rows])
    X_www = np.vstack([extract_m0_vec(r["canonical_url"], r["registered_domain"], True) for r in ext_rows])

    p_m0_raw = m0_full_b["model"].predict_proba(X_raw)[:, 1]
    p_m0_www = m0_full_b["model"].predict_proba(X_www)[:, 1]

    # Per-source comparison on N=1054 (raw vs www-stripped)
    by_source_n1054 = {}
    sources = sorted(set(r["source"] for r in ext_rows))
    for src in sources:
        idx = [i for i, r in enumerate(ext_rows) if r["source"] == src]
        ys = y_all[idx]
        p_raw_s = p_m0_raw[idx]
        p_www_s = p_m0_www[idx]
        pred_raw = (p_raw_s >= thr_m0).astype(int)
        pred_www = (p_www_s >= thr_m0).astype(int)
        by_source_n1054[src] = {
            "n": len(idx),
            "label": int(ys[0]),
            "raw_correct_rate": round(float(np.mean(pred_raw == ys)), 6),
            "raw_error_rate": round(float(np.mean(pred_raw != ys)), 6),
            "raw_mean_prob": round(float(np.mean(p_raw_s)), 6),
            "www_stripped_correct_rate": round(float(np.mean(pred_www == ys)), 6),
            "www_stripped_error_rate": round(float(np.mean(pred_www != ys)), 6),
            "www_stripped_mean_prob": round(float(np.mean(p_www_s)), 6),
        }

    # Now analyze N_CC = 104 from external_multimodal_probe_n240.jsonl
    probe_records = [
        json.loads(line)
        for line in (OUT_DIR / "external_multimodal_probe_n240.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    cc_records = [
        rec
        for rec in probe_records
        if rec["probe"]["infra"].get("status") == "success" and rec["probe"]["content"].get("status") == "success"
    ]
    y_cc = np.array([int(rec["sample"]["label_int"]) for rec in cc_records], dtype=int)

    X_m0_cc_raw, X_m0_cc_www = [], []
    X_m1_cc_raw, X_m1_cc_www = [], []
    X_m2_cc_raw, X_m2_cc_www = [], []

    for rec in cc_records:
        s = rec["sample"]
        pr = rec["probe"]
        v0_raw = extract_m0_vec(s["canonical_url"], s["registered_domain"], False)
        v0_www = extract_m0_vec(s["canonical_url"], s["registered_domain"], True)
        inf_f = extract_infrastructure_features(pr["infra"])
        v_inf = np.array([float(inf_f[k]) for k in INFRA_FEATURE_NAMES], dtype=np.float64)
        cnt_f = extract_content_features(pr["content"])
        v_cnt = np.array([float(cnt_f[k]) for k in CONTENT_FEATURE_NAMES], dtype=np.float64)

        X_m0_cc_raw.append(v0_raw)
        X_m0_cc_www.append(v0_www)
        X_m1_cc_raw.append(np.concatenate([v0_raw, v_inf]))
        X_m1_cc_www.append(np.concatenate([v0_www, v_inf]))
        X_m2_cc_raw.append(np.concatenate([v0_raw, v_inf, v_cnt]))
        X_m2_cc_www.append(np.concatenate([v0_www, v_inf, v_cnt]))

    X_m0_cc_raw = np.vstack(X_m0_cc_raw)
    X_m0_cc_www = np.vstack(X_m0_cc_www)
    X_m1_cc_raw = np.vstack(X_m1_cc_raw)
    X_m1_cc_www = np.vstack(X_m1_cc_www)
    X_m2_cc_raw = np.vstack(X_m2_cc_raw)
    X_m2_cc_www = np.vstack(X_m2_cc_www)

    p0_cc_raw = m0_cc_b["model"].predict_proba(X_m0_cc_raw)[:, 1]
    p0_cc_www = m0_cc_b["model"].predict_proba(X_m0_cc_www)[:, 1]
    p1_cc_raw = m1_cc_b["model"].predict_proba(X_m1_cc_raw)[:, 1]
    p1_cc_www = m1_cc_b["model"].predict_proba(X_m1_cc_www)[:, 1]
    p2_cc_raw = m2_cc_b["model"].predict_proba(X_m2_cc_raw)[:, 1]
    p2_cc_www = m2_cc_b["model"].predict_proba(X_m2_cc_www)[:, 1]

    # Per-source on N_CC = 104
    cc_by_source = {}
    for src in sorted(set(rec["sample"]["source"] for rec in cc_records)):
        idx = [i for i, rec in enumerate(cc_records) if rec["sample"]["source"] == src]
        ys = y_cc[idx]
        cc_by_source[src] = {
            "n_cc": len(idx),
            "label": int(ys[0]),
            "M0_CC_raw_acc": round(float(np.mean((p0_cc_raw[idx] >= thr_m0_cc) == ys)), 4),
            "M0_CC_www_acc": round(float(np.mean((p0_cc_www[idx] >= thr_m0_cc) == ys)), 4),
            "M1_CC_raw_acc": round(float(np.mean((p1_cc_raw[idx] >= thr_m1_cc) == ys)), 4),
            "M1_CC_www_acc": round(float(np.mean((p1_cc_www[idx] >= thr_m1_cc) == ys)), 4),
            "M2_CC_raw_acc": round(float(np.mean((p2_cc_raw[idx] >= thr_m2_cc) == ys)), 4),
            "M2_CC_www_acc": round(float(np.mean((p2_cc_www[idx] >= thr_m2_cc) == ys)), 4),
        }

    summary = {
        "n1054_m0_full_raw": compute_basic_metrics(y_all, p_m0_raw, thr_m0),
        "n1054_m0_full_www_stripped": compute_basic_metrics(y_all, p_m0_www, thr_m0),
        "n1054_by_source_raw_vs_www": by_source_n1054,
        "n104_cc_comparison": {
            "M0_CC_raw": compute_basic_metrics(y_cc, p0_cc_raw, thr_m0_cc),
            "M0_CC_www_stripped": compute_basic_metrics(y_cc, p0_cc_www, thr_m0_cc),
            "M1_CC_raw": compute_basic_metrics(y_cc, p1_cc_raw, thr_m1_cc),
            "M1_CC_www_stripped": compute_basic_metrics(y_cc, p1_cc_www, thr_m1_cc),
            "M2_CC_raw": compute_basic_metrics(y_cc, p2_cc_raw, thr_m2_cc),
            "M2_CC_www_stripped": compute_basic_metrics(y_cc, p2_cc_www, thr_m2_cc),
        },
        "n104_cc_by_source": cc_by_source,
    }

    out_path = OUT_DIR / "02b_external_forensic_www_ablation.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
