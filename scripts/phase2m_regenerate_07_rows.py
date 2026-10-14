"""Regenera las filas H3/E3/E4/E6/E7 de 07_ANALISIS_ESTADISTICO.md desde el CSV canónico.

La auditoría científica (MAYOR-2) demostró que la tabla del MD discrepaba del CSV
07_all_hypothesis_tests_table.csv en 5/14 filas (usa el F1 por-etapas de M4 en vez del
canónico). Este script reescribe SOLO las columnas numéricas de esas 5 filas directamente
desde el CSV (fuente de verdad, 14/14 reproducible), dejando intacta la columna narrativa
de diagnóstico. Emite también un apunte de corrección al final del encabezado de la sección.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MD = ROOT / "07_ANALISIS_ESTADISTICO.md"
CSV = ROOT / "artifacts" / "validacion_scopus_fase2" / "fase7_estadistica" / "07_all_hypothesis_tests_table.csv"

# comparison CSV -> id MD
ROW_ID = {
    "M0_vs_M4": "H3",
    "M2_vs_M4": "E3",
    "M4_vs_M5_FailClosed": "E4",
    "M0_vs_HybridM0_ConfigA": "E6",
    "M4_vs_ConfigC_HybridCascade": "E7",
}


def fmt_p(x: float) -> str:
    """Formatea p-value/holm como en el MD (científica con 3 decimales o decimal)."""
    if x == 0.0:
        return "< 1e-15"
    if x < 1e-4:
        return f"{x:.2e}".replace("e-0", "e-").replace("e-1", "e-1")
    return f"{x:.4f}"


def fmt_ci(cell: str) -> str:
    """Convierte '[0.027319, 0.080882]' del CSV a '[+0.0273, +0.0809]' estilo MD."""
    inner = cell.strip().strip("[]")
    lo, hi = [p.strip() for p in inner.split(",")]
    def s(v: str) -> str:
        fv = float(v)
        sign = "+" if fv >= 0 else "-"
        return f"{sign}{abs(fv):.4f}"
    return f"`[{s(lo)}, {s(hi)}]`"


def fmt_delta(x: float) -> str:
    sign = "+" if x >= 0 else "-"
    return f"{sign}{abs(x):.4f}"


rows = {r["comparison"]: r for r in csv.DictReader(CSV.open(encoding="utf-8"))}

md = MD.read_text(encoding="utf-8")
lines = md.split("\n")
changed = []
for i, line in enumerate(lines):
    m = re.match(r"^\|\s*\*\*(H3|E3|E4|E6|E7)\*\*\s*\|", line)
    if not m:
        continue
    rid = m.group(1)
    comp = next(k for k, v in ROW_ID.items() if v == rid)
    r = rows[comp]
    f1_a = float(r["f1_a"]); f1_b = float(r["f1_b"]); d = float(r["delta_f1_b_minus_a"])
    n01 = int(r["n01_b_correct_a_wrong"]); n10 = int(r["n10_a_correct_b_wrong"])
    p = float(r["mcnemar_p_exact"]); holm = float(r["p_holm_bonferroni"])
    g = float(r["effect_size_cohens_g"]); orr = float(r["effect_size_discordant_or"])
    ci_m = fmt_ci(r["delta_f1_ci95_sample_bootstrap"]); ci_c = fmt_ci(r["delta_f1_ci95_cluster_bootstrap"])
    delta_s = fmt_delta(d)
    # decide bold según significatividad Holm
    sig = r["significant_alpha_0_05_holm"].strip().lower() == "true"
    delta_cell = f"**`{delta_s}`**" if sig else f"`{delta_s}`"
    holm_cell = f"**`{fmt_p(holm)}`**" if sig else f"`{fmt_p(holm)}`"
    # etiqueta cualitativa original del MD ("Grande" para g >= 0.3), conservada
    g_label = " (Grande)" if g >= 0.3 else ""
    g_cell = f"**`{g:.4f}`{g_label}**" if sig else (f"`{g:.4f}`{g_label}" if g_label else f"`{g:.4f}`")
    # preserva la última celda (narrativa) tal cual
    last = line.split("|")[-2].strip()
    # Reconstruye la fila: mantenemos el prefijo de comparación y cohort del propio línea
    parts = [p.strip() for p in line.strip().strip("|").split("|")]
    # parts: 0 ID, 1 Comparación, 2 Cohorte, ... 14 narrativa
    compar = parts[1]; cohorte = parts[2]
    new_cells = [
        parts[0],
        compar,
        cohorte,
        f"`{f1_a:.4f}`",
        f"`{f1_b:.4f}`",
        delta_cell,
        ci_m,
        ci_c,
        f"`{n01}`",
        f"`{n10}`",
        f"`{fmt_p(p)}`",
        holm_cell,
        g_cell,
        f"`{orr:.2f}`",
        last,
    ]
    new_line = "| " + " | ".join(new_cells) + " |"
    changed.append((rid, comp, line, new_line))
    lines[i] = new_line

MD.write_text("\n".join(lines), encoding="utf-8")

for rid, comp, old, new in changed:
    print(f"=== {rid} ({comp}) ===")
    print("ANTES:", old)
    print("DESPU:", new)
    print()
print(f"{len(changed)} filas regeneradas desde el CSV canónico.")
