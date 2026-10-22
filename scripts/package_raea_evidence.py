"""Empaquetado exhaustivo de evidencias reproducibles para RAEA-Phish (Fase 9)."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ZIP_OUT = ROOT / "RAEA_PHISH_EVIDENCIA_CIENTIFICA.zip"

files_to_pack = [
    # Entregables Fase 0
    "AUDITORIA_SISTEMA.md",
    "REVISION_ORIGINALIDAD.md",
    "MATRIZ_TRABAJOS_RELACIONADOS.md",
    "BRECHA_INVESTIGACION.md",
    "COMPONENTES_REUTILIZABLES.md",
    # Entregables Fase 1
    "FORMULACION_MATEMATICA.md",
    "MODELO_DE_DECISION.md",
    "FUNCION_DE_COSTE.md",
    "POLITICA_RAEA.md",
    "PSEUDOCODIGO.md",
    "DIAGRAMA_ARQUITECTURA.md",
    # Entregables Fase 2
    "DATASETS_Y_PARTICIONES.md",
    "PROTOCOLO_ENTRENAMIENTO.md",
    "VALIDACION_ESTIMADORES.md",
    "calibration_results.csv",
    "availability_results.csv",
    "cost_estimation_results.csv",
    # Entregables Fase 3
    "DOCUMENTACION_IMPLEMENTACION.md",
    "tests/test_raea_policy.py",
    # Entregables Fase 4
    "PROTOCOLO_EXPERIMENTAL.md",
    "RESULTADOS_EXPERIMENTALES.md",
    "baseline_comparison.csv",
    "raea_results.csv",
    "early_exit_results.csv",
    "external_validation.csv",
    "coverage_risk.csv",
    "latency_results.csv",
    # Entregables Fase 5
    "ABLATION_PROTOCOL.md",
    "ABLATION_DISCUSSION.md",
    "ablation_results.csv",
    "component_contribution.csv",
    # Entregables Fase 6
    "STATISTICAL_ANALYSIS.md",
    "SENSITIVITY_ANALYSIS.md",
    "bootstrap_results.csv",
    "statistical_tests.csv",
    "confidence_intervals.csv",
    # Entregables Fase 7
    "INTEGRATION_REPORT.md",
    "browser_tests.csv",
    "failure_scenarios.csv",
    "operational_latency.csv",
    # Entregables Fase 8
    "AUDITORIA_CIENTIFICA.md",
    "AUDITORIA_TECNICA.md",
    "MATRIZ_TRAZABILIDAD.csv",
    "AFIRMACIONES_CIENTIFICAS.md",
    "LIMITACIONES.md",
    "RESULTADOS_REVALIDADOS.md",
    # Scripts
    "scripts/train_and_validate_raea_estimators.py",
    "scripts/run_raea_comparative_experiments.py",
    "scripts/run_raea_ablation_study.py",
    "scripts/run_raea_statistical_analysis.py",
    "scripts/run_raea_operational_test.py",
    "scripts/generate_traceability_matrix.py",
]

# Agregar directorio src/phishguard_orchestrator/raea/
raea_src_dir = ROOT / "src" / "phishguard_orchestrator" / "raea"
raea_src_files = [f.relative_to(ROOT) for f in raea_src_dir.glob("*.py")]

# Agregar modelos y artefactos en artifacts/raea/
raea_art_dir = ROOT / "artifacts" / "raea"
raea_art_files = [f.relative_to(ROOT) for f in raea_art_dir.glob("*.*")]

with zipfile.ZipFile(ZIP_OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for rel_path in files_to_pack:
        p = ROOT / rel_path
        if p.exists():
            z.write(p, arcname=rel_path)
            print(f"Empaquetado: {rel_path}")
            
    for rel_p in raea_src_files:
        p = ROOT / rel_p
        if p.exists():
            z.write(p, arcname=str(rel_p).replace("\\", "/"))
            print(f"Empaquetado codigo: {rel_p}")
            
    for rel_p in raea_art_files:
        p = ROOT / rel_p
        if p.exists():
            z.write(p, arcname=str(rel_p).replace("\\", "/"))
            print(f"Empaquetado artefacto: {rel_p}")

print(f"\n¡Paquete creado exitosamente en: {ZIP_OUT} (Tamaño: {ZIP_OUT.stat().st_size / 1024:.1f} KB)!")
