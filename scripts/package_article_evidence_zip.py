"""
Empaqueta los 9 artefactos obligatorios para la redaccion del articulo en
RAEA_PHISH_EVIDENCIA_PARA_ARTICULO.zip, verificando integridad y hashes.
"""
import zipfile
import hashlib
from pathlib import Path

def get_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    repo_root = Path(__file__).resolve().parent.parent
    zip_path = repo_root / "RAEA_PHISH_EVIDENCIA_PARA_ARTICULO.zip"

    artifacts_dir = repo_root / "artifacts" / "raea_final"
    cod_rep_dir = repo_root / "CODIGO_REPRODUCCION"
    fig_dir = artifacts_dir / "FIGURAS"

    # Define 9 components
    components = [
        # 1. RESUMEN_CIENTIFICO_DEFINITIVO.md
        (repo_root / "RESUMEN_CIENTIFICO_DEFINITIVO.md", "RESUMEN_CIENTIFICO_DEFINITIVO.md"),
        # 2. RESULTADOS_DEFINITIVOS.csv
        (artifacts_dir / "RESULTADOS_DEFINITIVOS.csv", "RESULTADOS_DEFINITIVOS.csv"),
        # 3. PREDICCIONES_INDIVIDUALES.csv
        (artifacts_dir / "PREDICCIONES_INDIVIDUALES.csv", "PREDICCIONES_INDIVIDUALES.csv"),
        # 4. ABLACIONES_DEFINITIVAS.csv
        (artifacts_dir / "ABLACIONES_DEFINITIVAS.csv", "ABLACIONES_DEFINITIVAS.csv"),
        # 5. ESTADISTICA_DEFINITIVA.csv
        (artifacts_dir / "ESTADISTICA_DEFINITIVA.csv", "ESTADISTICA_DEFINITIVA.csv"),
        # 6. COHORTE_Y_ETIQUETAS.csv
        (artifacts_dir / "COHORTE_Y_ETIQUETAS.csv", "COHORTE_Y_ETIQUETAS.csv"),
        # 7. AUDITORIA_FINAL.md
        (repo_root / "AUDITORIA_FINAL.md", "AUDITORIA_FINAL.md"),
        # 8. REPRODUCIBILIDAD/
        (cod_rep_dir / "reproduce_all.py", "REPRODUCIBILIDAD/reproduce_all.py"),
        (cod_rep_dir / "environment_specs.json", "REPRODUCIBILIDAD/environment_specs.json"),
        (cod_rep_dir / "test_reproduction_consistency.py", "REPRODUCIBILIDAD/test_reproduction_consistency.py"),
        # 9. FIGURAS/
        (fig_dir / "fig1_cost_coverage_tradeoff.png", "FIGURAS/fig1_cost_coverage_tradeoff.png"),
        (fig_dir / "fig2_risk_vs_coverage.png", "FIGURAS/fig2_risk_vs_coverage.png"),
        (fig_dir / "fig3_policy_comparison.png", "FIGURAS/fig3_policy_comparison.png"),
        (fig_dir / "fig4_ablations_analysis.png", "FIGURAS/fig4_ablations_analysis.png"),
    ]

    print(f"Creando {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for src_path, arc_name in components:
            if not src_path.exists():
                raise FileNotFoundError(f"Archivo requerido no existe: {src_path}")
            zf.write(src_path, arc_name)
            print(f"  + Agregado: {arc_name} ({src_path.stat().st_size} bytes)")

    sha256 = get_sha256(zip_path)
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"\nZIP CREADO EXITOSAMENTE:")
    print(f"Ruta: {zip_path}")
    print(f"Tamano: {size_mb:.2f} MB ({zip_path.stat().st_size} bytes)")
    print(f"SHA-256: {sha256}")

    # Guardar hash junto al zip
    hash_file = repo_root / "RAEA_PHISH_EVIDENCIA_PARA_ARTICULO.zip.sha256"
    hash_file.write_text(f"{sha256}  {zip_path.name}\n", encoding="utf-8")
    print(f"Hash guardado en: {hash_file.name}")

if __name__ == "__main__":
    main()
