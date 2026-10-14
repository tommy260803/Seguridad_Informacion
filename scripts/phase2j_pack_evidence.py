"""Empaqueta el paquete de evidencia definitivo y calcula su SHA-256.

Incluye TODO lo citado por los entregables:
  - entregables (los 7 + REPRODUCIBILIDAD.md)
  - artifacts/corrections_phase2/ completo (congelaciones, cohorte2, salidas phase2a-2i, junit)
  - scripts/phase2a..2i (los que construyen/evalúan la evidencia)
  - tests/test_corrections_phase2.py
  - artifacts/e2e_chrome/ + E2E_CHROME_RESULTS.md (si existen)
  - artefactos historicos citados en la reconciliacion

Produce:
  evidencia_phishpe_definitiva.zip
  evidencia_phishpe_definitiva.sha256   (hash del ZIP, formato estandar)
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidencia_phishpe_definitiva.zip"
SHA_OUT = ROOT / "evidencia_phishpe_definitiva.sha256"

INCLUDE_FILES = [
    # entregables
    "INFORME_FINAL_PHISHPE_CORREGIDO.md",
    "COMPARACION_ANTES_DESPUES.csv",
    "MATRIZ_TRAZABILIDAD_FINAL.csv",
    "VALIDACION_FINAL_AUTOMATICA.json",
    "LIMITACIONES_RESTANTES.md",
    "RESUMEN_DEFINITIVO_PARA_ARTICULO.md",
    "REPRODUCIBILIDAD.md",
    # informes historicos corregidos
    "07_ANALISIS_ESTADISTICO.md",
    "02_VALIDACION_EXTERNA.md",
    "03_EXTENSION_REAL.md",
    "05_CASCADA_ABLACIONES.md",
    # pruebas
    "tests/test_corrections_phase2.py",
    # scripts del protocolo
    "scripts/phase2a_freeze.py",
    "scripts/phase2b_acquire_cohort2.py",
    "scripts/phase2c_evaluate_cohort2.py",
    "scripts/phase2d_redirects_and_shorteners.py",
    "scripts/phase2e_verify_historical_stats.py",
    "scripts/phase2g_verify_manual_audit_regressions.py",
    "scripts/phase2h_build_deliverables.py",
    "scripts/phase2i_bug03_effect.py",
    "scripts/phase2j_pack_evidence.py",
    # dependencias
    "requirements-lock.txt",
    "pyproject.toml",
    # E2E Chrome
    "E2E_CHROME_RESULTS.md",
]

INCLUDE_DIRS = [
    "artifacts/corrections_phase2",
    "artifacts/e2e_chrome",
    "artifacts/validacion_scopus_fase2/fase7_estadistica",
]

EXCLUDE_SUFFIXES = {".pyc", ".log.tmp"}
EXCLUDE_NAMES = {"__pycache__"}


def want(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return False
    if path.suffix in EXCLUDE_SUFFIXES:
        return False
    return True


def main() -> None:
    entries: list[Path] = []
    for rel in INCLUDE_FILES:
        p = ROOT / rel
        if p.exists():
            entries.append(p)
        else:
            print(f"[omitido, no existe] {rel}")
    for rel in INCLUDE_DIRS:
        d = ROOT / rel
        if d.exists():
            entries.extend(sorted(x for x in d.rglob("*") if x.is_file() and want(x)))

    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "generated_utc": now,
        "freeze_manifest_sha256": None,
        "n_entries": len(entries),
        "entries": {},
    }
    fm = ROOT / "artifacts/corrections_phase2/freeze_manifest.json"
    if fm.exists():
        manifest["freeze_manifest_sha256"] = hashlib.sha256(fm.read_bytes()).hexdigest()

    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in sorted(set(entries)):
            arc = str(p.relative_to(ROOT)).replace("\\", "/")
            data = p.read_bytes()
            manifest["entries"][arc] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            zf.writestr(zipfile.ZipInfo(arc), data)

    # manifiesto interno del ZIP (ultimo, para incluir todos los hashes)
    with zipfile.ZipFile(OUT, "a", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(zipfile.ZipInfo("MANIFIESTO_EVIDENCIA.json"),
                    json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))

    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    SHA_OUT.write_text(f"{digest}  {OUT.name}\n", encoding="utf-8")

    print(f"ZIP: {OUT}")
    print(f"  entradas      : {manifest['n_entries']} + manifiesto")
    print(f"  bytes         : {OUT.stat().st_size}")
    print(f"  freeze sha256 : {manifest['freeze_manifest_sha256']}")
    print(f"  SHA-256       : {digest}")
    print(f"  archivo hash  : {SHA_OUT.name}")


if __name__ == "__main__":
    main()
