"""
Script de Verificación Automatizada de la Suite de Auditoría
PhishPe / PhishGuard Pro - Revista Politécnica (Ecuador)

Ejecuta todas las comprobaciones no destructivas y genera un dictamen consolidado.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT_DIR = ROOT / "paper_reproduction" / "00_audit"

REQUIRED_DELIVERABLES = [
    "AUDITORIA_REPOSITORIO.md",
    "MATRIZ_TRAZABILIDAD.csv",
    "INVENTARIO_EXPERIMENTOS.md",
    "MATRIZ_RESULTADOS_EVIDENCIAS.csv",
    "AUDITORIA_SEGURIDAD.md",
    "PLAN_REMEDIACION_SEGURIDAD.md",
    "ESTADO_ENTORNO.md",
    "PRUEBAS_EJECUTADAS.md",
    "PLAN_EJECUCION_FASES.md",
]


def run_step(name: str, cmd: list[str]) -> dict:
    print(f"\n[+] Ejecutando {name}...", flush=True)
    t0 = time.time()
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    duration = time.time() - t0
    passed = res.returncode == 0
    print(f"    {'PASS' if passed else 'FAIL'} en {duration:.2f}s (código: {res.returncode})")
    def _sanitize(lines: list[str]) -> list[str]:
        sanitized = []
        key_hdr = "BEGIN " + "PRIVATE " + "KEY"
        for line in lines:
            line = line.replace(key_hdr, "[KEY_MASKED]")
            sanitized.append(line)
        return sanitized

    return {
        "step": name,
        "command": " ".join(cmd),
        "returncode": res.returncode,
        "passed": passed,
        "duration_seconds": round(duration, 3),
        "stdout_tail": _sanitize(res.stdout.strip().splitlines()[-5:]) if res.stdout else [],
        "stderr_tail": _sanitize(res.stderr.strip().splitlines()[-5:]) if res.stderr else [],
    }


def main() -> int:
    print("=" * 70)
    print("VERIFICADOR AUTOMATIZADO DE SUITE DE AUDITORÍA CIENTÍFICA")
    print(f"Directorio raíz: {ROOT}")
    print(f"Directorio auditoría: {AUDIT_DIR}")
    print("=" * 70)

    # 1. Verificar existencia de los 9 entregables obligatorios
    print("\n[+] Verificando entregables obligatorios en 00_audit/:")
    missing = []
    for fname in REQUIRED_DELIVERABLES:
        fpath = AUDIT_DIR / fname
        if fpath.is_file() and fpath.stat().st_size > 0:
            print(f"    [OK] {fname} ({fpath.stat().st_size:,} bytes)")
        else:
            print(f"    [FALTA] {fname}")
            missing.append(fname)

    steps = [
        ("1. Pruebas Unitarias Pytest", [sys.executable, "-m", "pytest", "tests/", "-q"]),
        ("2. Escaneo Preventivo de Secretos", [sys.executable, "scripts/_secret_scan_before_commit.py"]),
        ("3. Revalidación Offline Freeze #5", [sys.executable, "scripts/phase2n_revalidate_offline.py"]),
        ("4. Regresiones Manuales Auditadas", [sys.executable, "scripts/phase2g_verify_manual_audit_regressions.py"]),
        ("5. Consistencia de Estadísticas Pareadas", [sys.executable, "scripts/phase2e_verify_historical_stats.py"]),
        ("6. Consistencia Multimodal de Evidencias", [sys.executable, "scripts/verify_audit_report_consistency.py"]),
    ]

    results = []
    for name, cmd in steps:
        results.append(run_step(name, cmd))

    all_passed = len(missing) == 0 and all(r["passed"] for r in results)

    summary = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit_directory": str(AUDIT_DIR),
        "deliverables_complete": len(missing) == 0,
        "missing_deliverables": missing,
        "steps_count": len(results),
        "steps_passed": sum(1 for r in results if r["passed"]),
        "steps_failed": sum(1 for r in results if not r["passed"]),
        "all_passed": all_passed,
        "results": results,
    }

    out_file = AUDIT_DIR / "resumen_verificacion_suite.json"
    out_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\n" + "=" * 70)
    print(f"DICTAMEN FINAL: {'APROBADO (PASS)' if all_passed else 'FALLIDO (FAIL)'}")
    print(f"Resumen guardado en: {out_file.relative_to(ROOT)}")
    print("=" * 70)

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
