"""
Reproducción Independiente de la Evaluación de Cohortes Externas
PhishPe / PhishGuard Pro - Revista Politécnica (Ecuador)

Este script permite re-ejecutar de forma exacta la evaluación comparativa
entre la Cohorte Histórica (A, N=1200), la Cohorte sin Malware (B, N=903),
y la Nueva Cohorte Especializada de Phishing (C, N=1200).
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "paper_reproduction" / "01_external_validation"

from src.phishguard_data.psl import PublicSuffixList
from src.phishguard_ml.features import UrlFeatureContext, extract_url_features
from src.phishguard_ml.hybrid_model import HybridM0Model


def compute_metrics(y_true: list[int], y_prob: list[float], threshold: float = 0.5) -> dict:
    y_pred = [1 if p >= threshold else 0 for p in y_prob]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    auc = roc_auc_score(y_true, y_prob) if len(set(y_true)) > 1 else None
    return {
        "n": len(y_true),
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "auc": round(float(auc), 4) if auc is not None else None,
    }


def main():
    parser = argparse.ArgumentParser(description="Reproducir evaluación de cohortes externas")
    parser.add_argument(
        "--models",
        choices=["m0_only", "all"],
        default="all",
        help="Modelos a evaluar ('m0_only' para evaluación rápida de M0, 'all' para incluir HybridM0)",
    )
    parser.add_argument(
        "--cohorts",
        choices=["A", "B", "C", "all"],
        default="all",
        help="Cohortes a evaluar (A=Histórica N=1200, B=Sin URLhaus N=903, C=Especializada Phishing N=1200)",
    )
    args = parser.parse_args()

    print("======================================================================")
    print("  PHISHPE: REPRODUCCIÓN DE EVALUACIÓN EXTERNA (REVISTA POLITÉCNICA)   ")
    print("======================================================================\n")

    m0_obj = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    clf = m0_obj["model"]
    feat_names = list(m0_obj["feature_names"])
    tau_m0 = float(m0_obj["threshold"])

    hybrid_model = HybridM0Model() if args.models == "all" else None

    # Cargar datasets
    cohort2_path = ROOT / "artifacts" / "corrections_phase2" / "cohort2" / "cohort2_dataset.csv"
    with open(cohort2_path, encoding="utf-8") as f:
        c_a_rows = list(csv.DictReader(f))
    c_b_rows = [r for r in c_a_rows if r["source"] != "urlhaus"]

    manifest_c_path = OUT_DIR / "external_cohort_manifest.csv"
    with open(manifest_c_path, encoding="utf-8") as f:
        c_c_rows = list(csv.DictReader(f))

    datasets = {}
    if args.cohorts in ("A", "all"):
        datasets["Cohorte A (Histórica N=1200)"] = c_a_rows
    if args.cohorts in ("B", "all"):
        datasets["Cohorte B (Histórica s/URLhaus N=903)"] = c_b_rows
    if args.cohorts in ("C", "all"):
        datasets["Cohorte C (Especializada Phishing N=1200)"] = c_c_rows

    print(f"{'Cohorte':<36} | {'Modelo':<18} | {'N':>5} | {'Prec':>7} | {'Recall':>7} | {'F1':>7} | {'FPR':>7} | {'AUC':>7}")
    print("-" * 105)

    for c_name, rows in datasets.items():
        y_true = []
        p_m0_orig = []
        p_m0_norm = []
        p_hybrid = []

        for r in rows:
            url = r["canonical_url"]
            reg = r["registered_domain"]
            v_lbl = r.get("validated_label")
            if v_lbl is not None:
                lbl = 1 if v_lbl == "PHISHING_VERIFICADO" else 0
            else:
                lbl = 1 if r.get("label") in ("phishing", "1", 1) else 0
            y_true.append(lbl)

            # M0 normalizado
            ctx = UrlFeatureContext(url, reg)
            f_norm = extract_url_features(ctx)
            x_norm = np.array([[f_norm[k] for k in feat_names]])
            p_m0_norm.append(float(clf.predict_proba(x_norm)[0][1]))

            # M0 original
            f_orig = dict(f_norm)
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            labels = host.split(".")
            if len(labels) > 2 and labels[0] == "www":
                f_orig["subdomain_count"] += 1.0
                f_orig["host_label_count"] += 1.0
            x_orig = np.array([[f_orig[k] for k in feat_names]])
            p_m0_orig.append(float(clf.predict_proba(x_orig)[0][1]))

            # HybridM0
            if hybrid_model:
                res = hybrid_model.predict(url, user_country="EC")
                p_hybrid.append(float(res["probability"]))

        # Reportar M0 Original
        m_orig = compute_metrics(y_true, p_m0_orig, tau_m0)
        print(f"{c_name:<36} | {'M0_Original':<18} | {m_orig['n']:>5} | {m_orig['precision']:>7.4f} | {m_orig['recall']:>7.4f} | {m_orig['f1']:>7.4f} | {m_orig['fpr']:>7.4f} | {m_orig['auc'] if m_orig['auc'] else 0.0:>7.4f}")

        # Reportar M0 Normalizado
        m_norm = compute_metrics(y_true, p_m0_norm, tau_m0)
        print(f"{c_name:<36} | {'M0_Normalizado':<18} | {m_norm['n']:>5} | {m_norm['precision']:>7.4f} | {m_norm['recall']:>7.4f} | {m_norm['f1']:>7.4f} | {m_norm['fpr']:>7.4f} | {m_norm['auc'] if m_norm['auc'] else 0.0:>7.4f}")

        # Reportar HybridM0
        if hybrid_model:
            m_hyb = compute_metrics(y_true, p_hybrid, 0.5)
            print(f"{c_name:<36} | {'HybridM0_ConfigC':<18} | {m_hyb['n']:>5} | {m_hyb['precision']:>7.4f} | {m_hyb['recall']:>7.4f} | {m_hyb['f1']:>7.4f} | {m_hyb['fpr']:>7.4f} | {m_hyb['auc'] if m_hyb['auc'] else 0.0:>7.4f}")
        print("-" * 105)


if __name__ == "__main__":
    main()
