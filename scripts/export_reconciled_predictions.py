"""
Exportación y Verificación de Predicciones Individuales de Cohortes Externas (N=1200)
PhishPe / PhishGuard Pro - Auditoría de Reproducibilidad Final
Revista Politécnica (Ecuador)
"""

from __future__ import annotations
import csv
from pathlib import Path
from urllib.parse import urlsplit
import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

PKG_DIR = ROOT / "paper_reproduction" / "06_publication_package"
MANIFESTS_DIR = PKG_DIR / "data_manifests"
EXT_DIR = ROOT / "paper_reproduction" / "01_external_validation"

MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)


def export_historical_cohort():
    print("=== [1] Exportando Predicciones Individuales: Cohorte Histórica N=1200 ===")
    hist_path = ROOT / "artifacts" / "corrections_phase2" / "eval" / "url_level_predictions.csv"
    with open(hist_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"Total registros cargados de url_level_predictions.csv: {len(rows)}")

    # Campos requeridos por el auditor:
    # ID, fuente, etiqueta verificada, versión del modelo, probabilidad de phishing, predicción final, partición y referencia al experimento original
    out_rows = []
    
    # 1. M0 Original (umbral 0.433937)
    tau_m0 = 0.433937
    for r in rows:
        p_orig = float(r["prob_M0_original"])
        lbl = 1 if r["label"] == "phishing" else 0
        pred = 1 if p_orig >= tau_m0 else 0
        out_rows.append({
            "id": r["cohort2_id"],
            "canonical_url": r["canonical_url"],
            "source": r["source"],
            "verified_label": "phishing" if lbl == 1 else "legitimate",
            "model_version": "M0_Baseline_Original_v020",
            "phishing_probability": f"{p_orig:.6f}",
            "final_prediction": "phishing" if pred == 1 else "legitimate",
            "partition": "external_validation_historical_n1200",
            "original_experiment_ref": "artifacts/corrections_phase2/eval/url_level_predictions.csv"
        })

    # 2. M0 Normalizado (umbral 0.433937)
    for r in rows:
        p_norm = float(r["prob_M0_normalizado"])
        lbl = 1 if r["label"] == "phishing" else 0
        pred = 1 if p_norm >= tau_m0 else 0
        out_rows.append({
            "id": r["cohort2_id"],
            "canonical_url": r["canonical_url"],
            "source": r["source"],
            "verified_label": "phishing" if lbl == 1 else "legitimate",
            "model_version": "M0_Baseline_Normalized_v020",
            "phishing_probability": f"{p_norm:.6f}",
            "final_prediction": "phishing" if pred == 1 else "legitimate",
            "partition": "external_validation_historical_n1200",
            "original_experiment_ref": "artifacts/corrections_phase2/eval/url_level_predictions.csv"
        })

    # 3. HybridM0 Config C (umbral 0.50)
    for r in rows:
        p_hyb = float(r["prob_configC"])
        lbl = 1 if r["label"] == "phishing" else 0
        pred = 1 if r["decision_configC"] == "phishing" else 0
        out_rows.append({
            "id": r["cohort2_id"],
            "canonical_url": r["canonical_url"],
            "source": r["source"],
            "verified_label": "phishing" if lbl == 1 else "legitimate",
            "model_version": "HybridM0_ConfigC_v020",
            "phishing_probability": f"{p_hyb:.6f}",
            "final_prediction": "phishing" if pred == 1 else "legitimate",
            "partition": "external_validation_historical_n1200",
            "original_experiment_ref": "artifacts/corrections_phase2/eval/url_level_predictions.csv"
        })

    fieldnames = [
        "id", "canonical_url", "source", "verified_label", "model_version",
        "phishing_probability", "final_prediction", "partition", "original_experiment_ref"
    ]

    out_file1 = MANIFESTS_DIR / "cohort_historical_n1200_individual_predictions.csv"
    out_file2 = EXT_DIR / "cohort_historical_n1200_individual_predictions.csv"
    for out_p in [out_file1, out_file2]:
        with open(out_p, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(out_rows)

    print(f"Exportados {len(out_rows)} registros de predicciones a {out_file1}")

    # Verificar matrices de confusión
    for mod in ["M0_Baseline_Original_v020", "M0_Baseline_Normalized_v020", "HybridM0_ConfigC_v020"]:
        sub = [r for r in out_rows if r["model_version"] == mod]
        yt = [1 if r["verified_label"] == "phishing" else 0 for r in sub]
        yp = [1 if r["final_prediction"] == "phishing" else 0 for r in sub]
        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
        f1 = f1_score(yt, yp)
        print(f"  [{mod}] TP={tp}, TN={tn}, FP={fp}, FN={fn}, F1={f1:.4f}")


def export_clean_phishing_cohort():
    print("\n=== [2] Exportando Predicciones Individuales: Cohorte Phishing Limpio N=1200 ===")
    manifest_c_path = EXT_DIR / "external_cohort_manifest.csv"
    with open(manifest_c_path, encoding="utf-8") as f:
        c_rows = list(csv.DictReader(f))

    print(f"Total registros cargados de external_cohort_manifest.csv: {len(c_rows)}")

    m0_obj = joblib.load(ROOT / "artifacts" / "url-baseline-0.2.0" / "model.joblib")
    clf = m0_obj["model"]
    feat_names = list(m0_obj["feature_names"])
    tau_m0 = float(m0_obj["threshold"])

    out_rows = []

    from src.phishguard_ml.features import UrlFeatureContext, extract_url_features

    for r in c_rows:
        url = r["canonical_url"]
        reg = r["registered_domain"]
        v_lbl = r["validated_label"]
        lbl = 1 if v_lbl == "PHISHING_VERIFICADO" else 0

        # M0 Normalizado
        ctx = UrlFeatureContext(url, reg)
        f_norm = extract_url_features(ctx)
        x_norm = np.array([[f_norm[k] for k in feat_names]])
        p_norm = float(clf.predict_proba(x_norm)[0][1])
        pred_norm = 1 if p_norm >= tau_m0 else 0

        out_rows.append({
            "id": r["cohort_id"],
            "canonical_url": url,
            "source": r["source"],
            "verified_label": "phishing" if lbl == 1 else "legitimate",
            "model_version": "M0_Baseline_Normalized_v020",
            "phishing_probability": f"{p_norm:.6f}",
            "final_prediction": "phishing" if pred_norm == 1 else "legitimate",
            "partition": "external_validation_clean_phishing_n1200",
            "original_experiment_ref": "paper_reproduction/01_external_validation/build_phishing_cohort.py"
        })

        # M0 Original (sin strip_www)
        f_orig = dict(f_norm)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        labels = host.split(".")
        if len(labels) > 2 and labels[0] == "www":
            f_orig["subdomain_count"] += 1.0
            f_orig["host_label_count"] += 1.0
        x_orig = np.array([[f_orig[k] for k in feat_names]])
        p_orig = float(clf.predict_proba(x_orig)[0][1])
        pred_orig = 1 if p_orig >= tau_m0 else 0

        out_rows.append({
            "id": r["cohort_id"],
            "canonical_url": url,
            "source": r["source"],
            "verified_label": "phishing" if lbl == 1 else "legitimate",
            "model_version": "M0_Baseline_Original_v020",
            "phishing_probability": f"{p_orig:.6f}",
            "final_prediction": "phishing" if pred_orig == 1 else "legitimate",
            "partition": "external_validation_clean_phishing_n1200",
            "original_experiment_ref": "paper_reproduction/01_external_validation/build_phishing_cohort.py"
        })

    fieldnames = [
        "id", "canonical_url", "source", "verified_label", "model_version",
        "phishing_probability", "final_prediction", "partition", "original_experiment_ref"
    ]

    out_file1 = MANIFESTS_DIR / "cohort_clean_phishing_n1200_individual_predictions.csv"
    out_file2 = EXT_DIR / "cohort_clean_phishing_n1200_individual_predictions.csv"
    for out_p in [out_file1, out_file2]:
        with open(out_p, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(out_rows)

    print(f"Exportados {len(out_rows)} registros de predicciones a {out_file1}")

    # Verificar matrices de confusión
    for mod in ["M0_Baseline_Original_v020", "M0_Baseline_Normalized_v020"]:
        sub = [r for r in out_rows if r["model_version"] == mod]
        yt = [1 if r["verified_label"] == "phishing" else 0 for r in sub]
        yp = [1 if r["final_prediction"] == "phishing" else 0 for r in sub]
        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
        f1 = f1_score(yt, yp)
        print(f"  [{mod}] TP={tp}, TN={tn}, FP={fp}, FN={fn}, F1={f1:.4f}")


if __name__ == "__main__":
    export_historical_cohort()
    export_clean_phishing_cohort()
