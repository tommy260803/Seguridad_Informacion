"""Auditoría de la ruta crítica de homógrafos en la cohorte2: qué URLs dispara cada configuración."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishguard_ml.homoglyphs import analyze_homoglyphs  # noqa: E402

EVAL = ROOT / "artifacts" / "corrections_phase2" / "eval"
rows = list(csv.DictReader((EVAL / "url_level_predictions.csv").open(encoding="utf-8")))

trig_c = [r for r in rows if float(r["prob_configC"]) > 0.9]
trig_a = [r for r in rows if float(r["prob_configA"]) > 0.9]
print("ConfigC triggers:", len(trig_c), " labels:", {l: sum(1 for r in trig_c if r["label"] == l) for l in ("phishing", "legitimate")})
print("ConfigA triggers:", len(trig_a), " labels:", {l: sum(1 for r in trig_a if r["label"] == l) for l in ("phishing", "legitimate")})

print("\nFirst 12 ConfigC triggers:")
for r in trig_c[:12]:
    host = r["canonical_url"].split("/")[2] if "://" in r["canonical_url"] else r["canonical_url"]
    res = analyze_homoglyphs(host, r["registered_domain"])
    print(f"  {r['label']:<10} {host[:44]:<46} reg={r['registered_domain'][:22]:<24} "
          f"dist={res['visual_edit_distance']} brand={res['closest_brand_target']} A={r['decision_configA']} C={r['decision_configC']}")

# Casos legítimos disparados por C (riesgo de falso positivo introducido)
fp_c = [r for r in trig_c if r["label"] == "legitimate"]
print("\nLegitimate URLs triggered by ConfigC:", len(fp_c))
for r in fp_c[:15]:
    print("   ", r["canonical_url"][:90], "| decisionC =", r["decision_configC"])
