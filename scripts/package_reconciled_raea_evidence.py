"""
Script de Empaquetado del Paquete de Evidencia Científica Corregida y Reconciliada:
RAEA_PHISH_EVIDENCIA_CIENTIFICA_CORREGIDA.zip
"""

from pathlib import Path
import zipfile
import hashlib

ROOT = Path(__file__).resolve().parent.parent
ZIP_PATH = ROOT / "RAEA_PHISH_EVIDENCIA_CIENTIFICA_CORREGIDA.zip"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    print("Iniciando empaquetado de RAEA_PHISH_EVIDENCIA_CIENTIFICA_CORREGIDA.zip...")

    files_to_pack = [
        # Informes de auditoría y protocolos
        "AUDITORIA_INICIAL_RAEA.md",
        "MATRIZ_PROBLEMAS.csv",
        "DEPENDENCIAS_EXPERIMENTALES.md",
        "ABSTENTION_PROTOCOL.md",
        "TESTS_ABSTENTION.md",
        "RISK_DEFINITIONS.md",
        "CORRECCIONES_RIESGO.md",
        "VALUE_OF_INFORMATION_AUDIT.md",
        "AVAILABILITY_AUDIT.md",
        "COST_AUDIT.md",
        "ABLATION_REVALIDATION.md",
        "RAEA_VS_M1.md",
        "STATISTICAL_AUDIT.md",
        "RESUMEN_MAESTRO_RAEA_CORREGIDO.md",
        
        # Código fuente RAEA
        "src/phishguard_orchestrator/raea/models.py",
        "src/phishguard_orchestrator/raea/risk.py",
        "src/phishguard_orchestrator/raea/availability.py",
        "src/phishguard_orchestrator/raea/cost.py",
        "src/phishguard_orchestrator/raea/policy.py",
        "src/phishguard_orchestrator/raea/adapter.py",
        "src/phishguard_orchestrator/raea/logger.py",
        "src/phishguard_orchestrator/raea/engine.py",
        "src/phishguard_orchestrator/raea/__init__.py",

        # Pruebas
        "tests/test_raea_policy.py",
        "tests/test_orchestrator.py",

        # Scripts
        "scripts/train_and_validate_raea_estimators.py",
        "scripts/run_raea_comparative_experiments.py",
        "scripts/run_raea_ablation_study.py",
        "scripts/run_raea_statistical_analysis.py",
        "scripts/run_raea_operational_test.py",
        "scripts/reconcile_abstentions_and_metrics.py",
        "scripts/reconcile_weighted_risk.py",
        "scripts/revalidate_ablation_with_guard_log.py",

        # Artefactos reconciliados y evidencia cuantitativa
        "artifacts/raea/raea_partitions.csv",
        "artifacts/raea/availability_estimator.joblib",
        "artifacts/raea/selective_predictions.csv",
        "artifacts/raea/abstention_by_class.csv",
        "artifacts/raea/selective_metrics.csv",
        "artifacts/raea/forced_decision_metrics.csv",
        "artifacts/raea/risk_recalculation.csv",
        "artifacts/raea/risk_decomposition.csv",
        "artifacts/raea/cost_sensitivity.csv",
        "artifacts/raea/voi_estimator_validation.csv",
        "artifacts/raea/guard_activation_log.csv",
        "artifacts/raea/ablation_revalidated.csv",
        "artifacts/raea/paired_raea_m1.csv",
        "artifacts/raea/operational_risk_comparison.csv",
        "artifacts/raea/statistical_tests_revalidated.csv",
        "artifacts/raea/baseline_comparison.csv",
        "artifacts/raea/raea_results.csv",
        "artifacts/raea/ablation_results.csv",
        "artifacts/raea/statistical_tests.csv",
    ]

    manifest_lines = ["filepath,sha256,size_bytes\n"]

    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_str in files_to_pack:
            p = ROOT / rel_str
            if not p.exists():
                print(f"[ALERTA] Archivo omitido (no encontrado): {rel_str}")
                continue
            sha = sha256_file(p)
            size = p.stat().st_size
            manifest_lines.append(f"{rel_str},{sha},{size}\n")
            zf.write(p, arcname=rel_str)
            print(f"Comprimido: {rel_str} ({size} bytes, SHA256: {sha[:10]}...)")

        # Añadir manifiesto de integridad
        manifest_content = "".join(manifest_lines)
        zf.writestr("MANIFEST_INTEGRIDAD_CORREGIDO.csv", manifest_content)
        print("Añadido MANIFEST_INTEGRIDAD_CORREGIDO.csv al archivo ZIP.")

    zip_size_mb = ZIP_PATH.stat().st_size / (1024 * 1024)
    print(f"\nPaquete final generado con éxito: {ZIP_PATH.name} ({zip_size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
