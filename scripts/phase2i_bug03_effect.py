"""Análisis del efecto real de BUG-03 (Punycode/homógrafos) sobre la cohorte2 congelada.

Compara Config A (código base ceb0c9e) frente a Config C (corregido) en el subconjunto
IDN/Punycode y en toda la cohorte, usando url_level_predictions.csv ya generado.
Además mide cuántas URLs disparan la ruta crítica de homógrafos en cada configuración.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

EVAL = ROOT / "artifacts" / "corrections_phase2" / "eval"
sys.path.insert(0, str(ROOT / "scripts"))

from phase2c_evaluate_cohort2 import safe_metrics  # noqa: E402

rows = list(csv.DictReader((EVAL / "url_level_predictions.csv").open(encoding="utf-8")))
y = np.array([1 if r["label"] == "phishing" else 0 for r in rows])
p_a = np.array([float(r["prob_configA"]) for r in rows])
p_c = np.array([float(r["prob_configC"]) for r in rows])
d_a = np.array([1 if r["decision_configA"] == "phishing" else 0 for r in rows])
d_c = np.array([1 if r["decision_configC"] == "phishing" else 0 for r in rows])
idn = np.array([r["is_idn_punycode"] == "1" for r in rows])
www = np.array([r["has_www"] == "1" for r in rows])

out: dict = {
    "note": "Efecto medido sobre la cohorte2 congelada (N=1200) usando predicciones por URL reales.",
    "whole_cohort": {
        "n": int(len(y)),
        "ConfigA": {k: safe_metrics(y, p_a, 0.5, y_pred_override=d_a)[k] for k in ("n", "f1", "fpr", "fnr")},
        "ConfigC": {k: safe_metrics(y, p_c, 0.5, y_pred_override=d_c)[k] for k in ("n", "f1", "fpr", "fnr")},
    },
    "idn_punycode_slice": {
        "n": int(idn.sum()),
        "n_phishing": int(y[idn].sum()),
        "n_legitimate": int((1 - y[idn]).sum()),
        "ConfigA": safe_metrics(y[idn], p_a[idn], 0.5, y_pred_override=d_a[idn]),
        "ConfigC": safe_metrics(y[idn], p_c[idn], 0.5, y_pred_override=d_c[idn]),
        "urls_where_A_and_C_differ": [
            {"url": rows[i]["canonical_url"], "label": rows[i]["label"],
             "decisionA": rows[i]["decision_configA"], "decisionC": rows[i]["decision_configC"],
             "probA": rows[i]["prob_configA"], "probC": rows[i]["prob_configC"]}
            for i in np.where((d_a != d_c) & idn)[0]
        ],
    },
    "www_slice": {
        "n": int(www.sum()),
        "ConfigA": safe_metrics(y[www], p_a[www], 0.5, y_pred_override=d_a[www]),
        "ConfigC": safe_metrics(y[www], p_c[www], 0.5, y_pred_override=d_c[www]),
    },
    "decisions_differ_total": int((d_a != d_c).sum()),
    "prob_shift_mean": round(float(np.abs(p_a - p_c).mean()), 6),
    "prob_shift_max": round(float(np.abs(p_a - p_c).max()), 6),
}

# Disparadores de la ruta crítica de homógrafos en cada configuración (prob > 0.9)
out["homoglyph_critical_path_triggers"] = {
    "ConfigA_prob_gt_0.9": int((p_a > 0.9).sum()),
    "ConfigC_prob_gt_0.9": int((p_c > 0.9).sum()),
    "note": "La ruta crítica de homógrafos fija la probabilidad en 0.99; se usa como proxy observable.",
}

dest = EVAL / "bug03_effect_on_cohort2.json"
dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({k: out[k] for k in ("whole_cohort", "idn_punycode_slice", "decisions_differ_total",
                                      "homoglyph_critical_path_triggers", "prob_shift_max")},
                 indent=2, ensure_ascii=False)[:3000])
