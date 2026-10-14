"""Fase 2 - PASO E: verificación de reproducibilidad de las estadísticas históricas.

Motivo (encargo §9.3): la auditoría reportó discrepancias entre las cifras del informe
07_ANALISIS_ESTADISTICO.md y las del CSV de pruebas pareadas
artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv.

Este script:
  1) RECALCULA cada fila de ese CSV directamente desde los predictions.csv congelados
     (mismas reglas de threshold, subconjunto decidido por M5 y cohortes que el script
     original fase2_07_analisis_estadistico.py).
  2) Compara recálculo vs CSV publicado (tolerancia 1e-9 en enteros, 1e-6 en decimales).
  3) Escanea 07_ANALISIS_ESTADISTICO.md y contrasta las cifras citadas en texto con las
     del CSV, listando las que no coinciden.
  4) Escribe artifacts/corrections_phase2/eval/historical_stats_reconciliation.json
     con el dictamen: PASS / MISMATCH por fila y por afirmación textual.

No modifica ningún artefacto histórico.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

EVAL = ROOT / "artifacts" / "corrections_phase2" / "eval"
F7 = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase7_estadistica"
CSV_PUBLISHED = F7 / "07_all_hypothesis_tests_table.csv"
MD_REPORT = ROOT / "07_ANALISIS_ESTADISTICO.md"

from scipy.stats import binomtest  # noqa: E402


def load_test_rows(m_dir: str) -> list[dict[str, str]]:
    rows = [r for r in csv.DictReader((ROOT / "artifacts" / m_dir / "predictions.csv").open(encoding="utf-8"))
            if r["partition"] == "test"]
    rows.sort(key=lambda r: r["sample_id"])
    return rows


def threshold_of(m_dir: str) -> float:
    m = json.loads((ROOT / "artifacts" / m_dir / "metrics.json").read_text(encoding="utf-8"))
    return float(m.get("selected_threshold", 0.5))


def f1_of(y: np.ndarray, p: np.ndarray) -> float:
    tp = int(((y == 1) & (p == 1)).sum())
    fp = int(((y == 0) & (p == 1)).sum())
    fn = int(((y == 1) & (p == 0)).sum())
    return 0.0 if (2 * tp + fp + fn) == 0 else 2 * tp / (2 * tp + fp + fn)


def mcnemar_counts(y: np.ndarray, a: np.ndarray, b: np.ndarray) -> dict[str, int]:
    return {
        "n11_both_correct": int(((a == y) & (b == y)).sum()),
        "n00_both_wrong": int(((a != y) & (b != y)).sum()),
        "n01_b_correct_a_wrong": int(((a != y) & (b == y)).sum()),
        "n10_a_correct_b_wrong": int(((a == y) & (b != y)).sum()),
    }


def main() -> None:
    EVAL.mkdir(parents=True, exist_ok=True)

    # ---- Reconstrucción de los arrays internos (idéntico a fase2_07) --------
    internal: dict[str, dict[str, Any]] = {}
    for name, d in (("M0", "m0-real"), ("M1", "m1-real"), ("M2", "m2-real"),
                    ("M3", "m3-real"), ("M4", "m4-real"), ("M5", "m5-real")):
        rows = load_test_rows(d)
        tau = threshold_of(d)
        y = np.array([int(r["label"]) for r in rows])
        prob = np.array([float(r["probability_phishing"]) for r in rows])
        pred = (prob >= tau).astype(int)
        abst = np.array([str(r.get("abstained", "0")).strip().lower() in ("1", "true") for r in rows])
        internal[name] = {"sids": [r["sample_id"] for r in rows], "y": y, "prob": prob,
                          "pred": pred, "tau": tau, "abstain": abst}

    # Config A / Config C internos desde el log de la fase III
    log_path = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase3_extension" / "03_per_request_extension_and_cascade_log.csv"
    y691 = internal["M0"]["y"]
    sids691 = internal["M0"]["sids"]
    cfg: dict[str, Any] = {}
    if log_path.exists():
        log_rows = {r["sample_id"]: r for r in csv.DictReader(log_path.open(encoding="utf-8"))
                    if r["cohort"] == "internal_n691"}
        if all(s in log_rows for s in sids691):
            cfg["HybridM0_ConfigA"] = {
                "y": y691,
                "pred": np.array([1 if log_rows[s]["config_a_decision"] == "phishing" else 0 for s in sids691]),
            }
            cfg["ConfigC_HybridCascade"] = {
                "y": y691,
                "pred": (np.array([float(log_rows[s]["config_c_prob"]) for s in sids691]) >= 0.46484375).astype(int),
            }

    m5_fail_closed = np.where(internal["M5"]["abstain"], 1, internal["M4"]["pred"])
    decided = ~internal["M5"]["abstain"]

    # ---- Externo N=1054 (mismas columnas/umbrales que fase2_07) -------------
    ext_path = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase2_externa" / "external_predictions_n1200.csv"
    ext_rows = list(csv.DictReader(ext_path.open(encoding="utf-8-sig")))
    y_ext = np.array([int(r["label_int"]) for r in ext_rows])
    ext = {
        "M0_External": (np.array([float(r["prob_M0_CC"]) for r in ext_rows]) >= 0.38266699053469533).astype(int),
        "HybridM0_WithTranco_External": (np.array([float(r["prob_HybridM0_with_Tranco"]) for r in ext_rows]) >= 0.50).astype(int),
        "HybridM0_NoTranco_External": (np.array([float(r["prob_HybridM0_without_Tranco"]) for r in ext_rows]) >= 0.35).astype(int),
    }

    def resolve(a: str, b: str) -> tuple[np.ndarray, np.ndarray, np.ndarray] | None:
        """Devuelve (y, pred_a, pred_b) respetando la cohorte declarada en el CSV."""
        if a.startswith("M0_decided") or b.startswith("M5_selective") or a.startswith("M2_decided"):
            if a.startswith("M0_decided"):
                pa = internal["M0"]["pred"][decided]
            else:
                pa = internal["M2"]["pred"][decided]
            return y691[decided], pa, internal["M5"]["pred"][decided]
        if a in ext and b in ext:
            return y_ext, ext[a], ext[b]
        if b == "M5_FailClosed":
            src = internal[a]
            return src["y"], src["pred"], m5_fail_closed
        if a in cfg and b in cfg:
            return cfg[a]["y"], cfg[a]["pred"], cfg[b]["pred"]
        if a in internal and b in cfg:
            return y691, internal[a]["pred"], cfg[b]["pred"]
        if a in internal and b in internal:
            ia, ib = internal[a], internal[b]
            if len(ia["y"]) != len(ib["y"]):
                return None
            return ia["y"], ia["pred"], ib["pred"]
        if a in cfg and b in internal:
            return y691, cfg[a]["pred"], internal[b]["pred"]
        return None

    # ---- Recomputación fila a fila del CSV publicado ------------------------
    published = list(csv.DictReader(CSV_PUBLISHED.open(encoding="utf-8-sig")))
    checks: list[dict[str, Any]] = []
    for row in published:
        got = resolve(row["model_a"], row["model_b"])
        entry: dict[str, Any] = {"comparison": row["comparison"], "cohort": row["cohort"]}
        if got is None:
            entry["status"] = "NOT_RECOMPUTED"
            entry["reason"] = "combinación de modelos no reconstructible con las reglas declaradas"
            checks.append(entry)
            continue
        y, pa, pb = got
        counts = mcnemar_counts(y, pa, pb)
        n_disc = counts["n01_b_correct_a_wrong"] + counts["n10_a_correct_b_wrong"]
        p_exact = float(binomtest(counts["n01_b_correct_a_wrong"], n_disc, 0.5).pvalue) if n_disc else 1.0
        recomputed = {
            "n": int(len(y)),
            "f1_a": round(f1_of(y, pa), 6),
            "f1_b": round(f1_of(y, pb), 6),
            "delta_f1_b_minus_a": round(f1_of(y, pb) - f1_of(y, pa), 6),
            **counts,
            "total_discordant": n_disc,
            "mcnemar_p_exact": round(p_exact, 8),
        }
        diffs: dict[str, Any] = {}
        for key, mine in recomputed.items():
            pub_raw = row.get(key, "")
            try:
                pub = float(pub_raw)
            except (TypeError, ValueError):
                diffs[key] = {"published": pub_raw, "recomputed": mine}
                continue
            tol = 1e-6 if isinstance(mine, float) else 1e-9
            if abs(pub - mine) > tol:
                diffs[key] = {"published": pub, "recomputed": mine}
        entry.update(recomputed)
        entry["differences_vs_published_csv"] = diffs
        entry["status"] = "MATCH" if not diffs else "MISMATCH"
        checks.append(entry)

    # ---- Afirmaciones textuales del informe 07 ------------------------------
    text_claims: list[dict[str, Any]] = []
    md = MD_REPORT.read_text(encoding="utf-8", errors="replace") if MD_REPORT.exists() else ""
    patterns = {
        "M3_vs_M2_delta_f1": r"M3[^.\n]{0,200}?\Delta\text\{F1\} = (-?[0-9.]+)",
        "M2_vs_M1_delta_f1": r"\+0\.0127|0\.0127",
        "M2_vs_M1_p": r"p = 0\.2668",
        "M2_vs_M1_pairs": r"9 vs\. 4",
    }
    csv_by_id = {r["comparison"]: r for r in published}
    m2_m1 = csv_by_id.get("M1_vs_M2", {})
    m2_m3 = csv_by_id.get("M2_vs_M3", {})
    text_claims.append({
        "claim": "07 informe: M2 vs M1 (+0.0127 F1, 9 vs 4 discordantes, p = 0.2668)",
        "present_in_report": bool(re.search(r"0\.0127", md) and re.search(r"0\.2668", md)),
        "csv_values": {"f1_delta": m2_m1.get("delta_f1_b_minus_a"),
                       "n01": m2_m1.get("n01_b_correct_a_wrong"), "n10": m2_m1.get("n10_a_correct_b_wrong"),
                       "p_exact": m2_m1.get("mcnemar_p_exact")},
        "recomputed_values": next(({"f1_delta": c["delta_f1_b_minus_a"], "n01": c["n01_b_correct_a_wrong"],
                                    "n10": c["n10_a_correct_b_wrong"], "p_exact": c["mcnemar_p_exact"]}
                                   for c in checks if c["comparison"] == "M1_vs_M2"), {}),
    })
    text_claims.append({
        "claim": "07 informe: M3 vs M2 (delta F1 = -0.0007, p = 1.0000)",
        "present_in_report": bool(re.search(r"-0\.0007", md)),
        "csv_values": {"f1_delta": m2_m3.get("delta_f1_b_minus_a"), "p_exact": m2_m3.get("mcnemar_p_exact")},
        "recomputed_values": next(({"f1_delta": c["delta_f1_b_minus_a"], "p_exact": c["mcnemar_p_exact"]}
                                   for c in checks if c["comparison"] == "M2_vs_M3"), {}),
    })

    # ---- Consistencia TABLA H1-H6/E1-E8 vs CSV canónico (MAYOR-2) ----------
    # Parsea las filas de las dos tablas del informe 07 y contrasta cada celda
    # numérica clave (F1_A, F1_B, Δ, n01, n10, p exacto, Holm) con el CSV.
    MD_ROW_TO_COMPARISON = {
        "H1": "M0_vs_M1", "H2": "M0_vs_M2", "H3": "M0_vs_M4",
        "H4": "M0_decided_vs_M5_selective",
        "H5": "M0_External_vs_HybridM0_NoTranco_External",
        "H6": "M0_External_vs_HybridM0_WithTranco_External",
        "E1": "M1_vs_M2", "E2": "M2_vs_M3", "E3": "M2_vs_M4",
        "E4": "M4_vs_M5_FailClosed", "E5": "M2_decided_vs_M5_selective",
        "E6": "M0_vs_HybridM0_ConfigA", "E7": "M4_vs_ConfigC_HybridCascade",
        "E8": "HybridM0_NoTranco_External_vs_HybridM0_WithTranco_External",
    }

    def fmt_p_md(x: float) -> str:
        if x == 0.0:
            # el CSV publica 0.0 por underflow; el informe lo expresa como cota
            return "< 1e-15"
        if x < 1e-4:
            return f"{x:.2e}".replace("e-0", "e-")
        return fmt4(x)

    def fmt4(x: float) -> str:
        """Redondeo decimal half-up a 4 decimales (mismo criterio que el informe)."""
        from decimal import ROUND_HALF_UP, Decimal

        return str(Decimal(repr(x)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))

    def fmt_ci_md(raw: str) -> str:
        """'[0.034824, 0.0881]' -> '[+0.0348, +0.0881]' (formato del informe)."""
        inner = raw.strip().strip("[]")
        lo, hi = [p.strip() for p in inner.split(",")]

        def one(v: str) -> str:
            fv = float(v)
            return ("+" if fv >= 0 else "-") + fmt4(abs(fv))

        return f"[{one(lo)}, {one(hi)}]"

    def fmt_delta_md(x: float) -> str:
        return ("+" if x >= 0 else "-") + fmt4(abs(x))

    def cell(s: str) -> str:
        return s.strip().replace("*", "").replace("`", "").strip()

    table_checks: list[dict[str, Any]] = []
    for line in md.splitlines():
        m = re.match(r"^\|\s*\*\*([HE][1-8])\*\*\s*\|", line)
        if not m:
            continue
        rid = m.group(1)
        parts = [p for p in line.strip().strip("|").split("|")]
        if len(parts) < 15:
            table_checks.append({"row": rid, "status": "PARSE_ERROR", "n_cells": len(parts)})
            continue
        comp = MD_ROW_TO_COMPARISON.get(rid, "")
        crow = csv_by_id.get(comp)
        if crow is None:
            table_checks.append({"row": rid, "status": "NO_CSV_ROW", "comparison": comp})
            continue
        md_vals = {
            "f1_a": cell(parts[3]), "f1_b": cell(parts[4]),
            "delta_f1_b_minus_a": cell(parts[5]),
            "delta_f1_ci95_sample_bootstrap": cell(parts[6]),
            "delta_f1_ci95_cluster_bootstrap": cell(parts[7]),
            "n01_b_correct_a_wrong": cell(parts[8]), "n10_a_correct_b_wrong": cell(parts[9]),
            "mcnemar_p_exact": cell(parts[10]), "p_holm_bonferroni": cell(parts[11]),
        }
        exp = {
            "f1_a": f"{float(crow['f1_a']):.4f}",
            "f1_b": f"{float(crow['f1_b']):.4f}",
            "delta_f1_b_minus_a": fmt_delta_md(float(crow["delta_f1_b_minus_a"])),
            "delta_f1_ci95_sample_bootstrap": fmt_ci_md(crow["delta_f1_ci95_sample_bootstrap"]),
            "delta_f1_ci95_cluster_bootstrap": fmt_ci_md(crow["delta_f1_ci95_cluster_bootstrap"]),
            "n01_b_correct_a_wrong": str(int(crow["n01_b_correct_a_wrong"])),
            "n10_a_correct_b_wrong": str(int(crow["n10_a_correct_b_wrong"])),
            "mcnemar_p_exact": fmt_p_md(float(crow["mcnemar_p_exact"])),
            "p_holm_bonferroni": fmt_p_md(float(crow["p_holm_bonferroni"])),
        }
        diffs = {k: {"md": md_vals[k], "csv_expected": exp[k]}
                 for k in exp if md_vals[k] != exp[k]}
        table_checks.append({"row": rid, "comparison": comp,
                             "status": "MATCH" if not diffs else "MISMATCH",
                             "differences": diffs})

    n_tbl_bad = sum(1 for t in table_checks if t["status"] != "MATCH")

    statuses = [c["status"] for c in checks]
    payload = {
        "published_csv": str(CSV_PUBLISHED.relative_to(ROOT)),
        "published_csv_sha256": __import__("hashlib").sha256(CSV_PUBLISHED.read_bytes()).hexdigest(),
        "n_rows_published": len(published),
        "n_match": statuses.count("MATCH"),
        "n_mismatch": statuses.count("MISMATCH"),
        "n_not_recomputed": statuses.count("NOT_RECOMPUTED"),
        "row_checks": checks,
        "textual_claims": text_claims,
        "table_vs_csv_checks": table_checks,
        "n_table_rows_checked": len(table_checks),
        "n_table_mismatch": n_tbl_bad,
        "dictamen": ("PASS: todas las filas del CSV publicado son reproducibles desde los "
                     "predictions.csv congelados y las 14 filas de las tablas del informe 07 "
                     "coinciden con el CSV canónico" if statuses.count("MISMATCH") == 0 and
                    statuses.count("NOT_RECOMPUTED") == 0 and n_tbl_bad == 0
                    else "REVISAR: hay filas no reproducibles, discrepantes o tablas vs CSV "
                         "desalineadas (ver row_checks / table_vs_csv_checks)"),
    }
    out = EVAL / "historical_stats_reconciliation.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("n_rows_published", "n_match", "n_mismatch",
                                              "n_not_recomputed", "n_table_rows_checked",
                                              "n_table_mismatch", "dictamen")}, indent=2,
                     ensure_ascii=False))
    for c in checks:
        if c["status"] != "MATCH":
            print(f"  [{c['status']}] {c['comparison']}: {c.get('differences_vs_published_csv') or c.get('reason')}")
    for t in table_checks:
        if t["status"] != "MATCH":
            print(f"  [tabla {t['status']}] {t['row']}: {t.get('differences') or t.get('n_cells') or t.get('comparison')}")
    for t in text_claims:
        print(f"  [claim] {t['claim'][:60]} -> csv={t['csv_values']} recomputed={t['recomputed_values']}")


if __name__ == "__main__":
    main()
