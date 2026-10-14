"""Mide el impacto de la corrección C-2 (heurística punycode+marca) sobre la cohorte2.

Para cada host de la cohorte congelada, ejecuta analyze_homoglyphs del código BASELINE
(snapshot inmutable ceb0c9e) y del código ACTUAL (con BUG-08 ya corregido), y clasifica:
  - hosts con etiqueta xn-- y dominio registrado de marca conocida (disparador del FP)
  - hosts donde baseline y actual ya difieren (regresión BUG-08)
No toca modelos, etiquetas ni re-sondea red: es 100% offline.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "corrections_phase2"
EVAL = OUT / "eval"
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.homoglyphs import analyze_homoglyphs as current_analyze  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


baseline = load_module("baseline_homoglyphs",
                       OUT / "baseline_original" / "src__phishguard_ml__homoglyphs.py")

BRANDS = {"apple.com", "microsoft.com", "google.com", "paypal.com",
          "facebook.com", "amazon.com", "netflix.com", "instagram.com"}

rows = list(csv.DictReader((OUT / "cohort2" / "cohort2_dataset.csv").open(encoding="utf-8")))
print(f"cohort2 rows: {len(rows)}")

n_puny = 0
n_puny_brand = 0          # disparador del FP: etiqueta xn-- Y dominio registrado de marca
disparadores = []
baseline_vs_current_diff = 0
diff_examples = []

for r in rows:
    host = r["host"] if "host" in r else r.get("hostname", "")
    reg = r.get("registered_domain", "")
    has_puny = any(lbl.lower().startswith("xn--") for lbl in host.split("."))
    if has_puny:
        n_puny += 1
        if reg.lower().rstrip(".") in BRANDS:
            n_puny_brand += 1
            disparadores.append({"cohort2_id": r["cohort2_id"], "host": host,
                                 "registered_domain": reg, "label": r["label"]})
    b = baseline.analyze_homoglyphs(host, reg)
    c = current_analyze(host, reg)
    # clave común a ambas versiones (la baseline no expone 'is_spoofing')
    b_spoof = bool(b["homoglyph_brand_spoofing_detected"])
    c_spoof = bool(c["homoglyph_brand_spoofing_detected"])
    if b_spoof != c_spoof:
        baseline_vs_current_diff += 1
        if len(diff_examples) < 20:
            diff_examples.append({"cohort2_id": r["cohort2_id"], "host": host,
                                  "registered_domain": reg, "label": r["label"],
                                  "baseline": b_spoof, "current": c_spoof})

res = {
    "n_rows": len(rows),
    "n_hosts_con_etiqueta_xn--": n_puny,
    "n_disparadores_FP_xn--_mas_dominio_marca": n_puny_brand,
    "disparadores": disparadores,
    "n_baseline_vs_current_is_spoofing_diff": baseline_vs_current_diff,
    "diff_examples": diff_examples,
    "conclusion": ("NINGÚN host de la cohorte2 activa el disparador del falso positivo (xn-- + "
                   "dominio registrado de marca): la corrección C-2 es una corrección latente sin "
                   "efecto sobre las métricas de la cohorte congelada."
                   if n_puny_brand == 0 else
                   f"ATENCIÓN: {n_puny_brand} hosts de la cohorte2 activan el disparador; la "
                   "corrección C-2 SÍ puede afectar Config C y deben recalcularse las métricas."),
}
(EVAL / "bug03_c2_fix_impact_on_cohort2.json").write_text(
    json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({k: v for k, v in res.items() if k not in ("disparadores", "diff_examples")},
                 indent=2, ensure_ascii=False))
print("diff baseline-vs-current (regresión BUG-08) ejemplos:", json.dumps(diff_examples[:5],
                                                                           ensure_ascii=False))
