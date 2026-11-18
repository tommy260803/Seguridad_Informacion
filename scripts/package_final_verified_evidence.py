"""Script de empaquetado del paquete de evidencia científica final verificada:
RAEA_PHISH_EVIDENCIA_FINAL_VERIFICADA.zip
"""
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / "RAEA_PHISH_EVIDENCIA_FINAL_VERIFICADA.zip"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main():
    print(f"Empaquetando evidencia consolidada en: {ZIP_PATH.name}...")

    # Archivos obligatorios según sección 6 del requerimiento
    items = [
        # 1. Resumen maestro
        (ROOT / "RESUMEN_MAESTRO_FINAL.md", "RESUMEN_MAESTRO_FINAL.md"),
        # 2. Auditoría de correcciones
        (ROOT / "AUDITORIA_CORRECCIONES.md", "AUDITORIA_CORRECCIONES.md"),
        # 3. Datos y etiquetas
        (ROOT / "artifacts" / "raea_final" / "DATOS_Y_ETIQUETAS.csv", "DATOS_Y_ETIQUETAS.csv"),
        # 4. Predicciones y decisiones individuales
        (ROOT / "artifacts" / "raea_final" / "PREDICCIONES_Y_DECISIONES.csv", "PREDICCIONES_Y_DECISIONES.csv"),
        # 5. Resultados comparativos
        (ROOT / "artifacts" / "raea_final" / "RESULTADOS_COMPARATIVOS.csv", "RESULTADOS_COMPARATIVOS.csv"),
        # 6. Ablaciones verificadas
        (ROOT / "artifacts" / "raea_final" / "ABLACIONES_VERIFICADAS.csv", "ABLACIONES_VERIFICADAS.csv"),
        # 7. Estadística y riesgo
        (ROOT / "artifacts" / "raea_final" / "ESTADISTICA_Y_RIESGO.csv", "ESTADISTICA_Y_RIESGO.csv"),
        # 8. Registro de pruebas
        (ROOT / "PRUEBAS_Y_REPRODUCCION.txt", "PRUEBAS_Y_REPRODUCCION.txt"),
        # 10. Matriz de trazabilidad
        (ROOT / "MATRIZ_TRAZABILIDAD.csv", "MATRIZ_TRAZABILIDAD.csv"),
        # Metadata y pre-registro
        (ROOT / "artifacts" / "raea_final" / "run_metadata.json", "run_metadata.json"),
        (ROOT / "configs" / "raea_final_experiment.json", "configs/raea_final_experiment.json"),
        # 9. Código mínimo de reproducción
        (ROOT / "scripts" / "raea_label_audit.py", "CODIGO_REPRODUCCION/raea_label_audit.py"),
        (ROOT / "scripts" / "raea_final_verification.py", "CODIGO_REPRODUCCION/raea_final_verification.py"),
        (ROOT / "CODIGO_REPRODUCCION" / "test_reproduction_consistency.py", "CODIGO_REPRODUCCION/test_reproduction_consistency.py"),
        (ROOT / "CODIGO_REPRODUCCION" / "README_REPRODUCCION.md", "CODIGO_REPRODUCCION/README_REPRODUCCION.md"),
    ]

    manifest_lines = ["archivo,sha256,bytes\n"]

    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for src_path, arcname in items:
            assert src_path.exists(), f"Archivo requerido ausente: {src_path}"
            data = src_path.read_bytes()
            h = sha256_bytes(data)
            size = len(data)
            manifest_lines.append(f"{arcname},{h},{size}\n")
            zf.writestr(arcname, data)
            print(f"  + {arcname} ({size} B, SHA-256: {h[:12]}...)")

        # Escribir manifiesto de integridad dentro del ZIP
        manifest_str = "".join(manifest_lines)
        zf.writestr("MANIFEST_INTEGRIDAD.csv", manifest_str)
        print("  + MANIFEST_INTEGRIDAD.csv")

    zip_bytes = ZIP_PATH.read_bytes()
    zip_sha = sha256_bytes(zip_bytes)
    zip_mb = len(zip_bytes) / (1024 * 1024)
    print(f"\nPaquete final generado:")
    print(f"  Ruta: {ZIP_PATH.resolve()}")
    print(f"  Tamaño: {zip_mb:.2f} MB ({len(zip_bytes)} bytes)")
    print(f"  SHA-256: {zip_sha}")


if __name__ == "__main__":
    main()
