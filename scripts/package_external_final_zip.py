"""
Empaqueta el entregable unico obligatorio:
RAEA_PHISH_EVIDENCIA_EXTERNA_FINAL.zip
con exactamente los 8 componentes especificados.
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
    zip_path = repo_root / "RAEA_PHISH_EVIDENCIA_EXTERNA_FINAL.zip"

    auto_dir = repo_root / "autonomous_reproduction_suite"
    fig_dir = repo_root / "FIGURAS"

    items_to_pack = [
        # 1. RESUMEN_MAESTRO_FINAL.md
        (repo_root / "RESUMEN_MAESTRO_FINAL.md", "RESUMEN_MAESTRO_FINAL.md"),
        # 2. PROTOCOLO_Y_CONGELAMIENTO.md
        (repo_root / "PROTOCOLO_Y_CONGELAMIENTO.md", "PROTOCOLO_Y_CONGELAMIENTO.md"),
        # 3. COHORTE_EXTERNA.csv
        (repo_root / "COHORTE_EXTERNA.csv", "COHORTE_EXTERNA.csv"),
        # 4. PREDICCIONES_EXTERNAS.csv
        (repo_root / "PREDICCIONES_EXTERNAS.csv", "PREDICCIONES_EXTERNAS.csv"),
        # 5. RESULTADOS_Y_ESTADISTICA.csv
        (repo_root / "RESULTADOS_Y_ESTADISTICA.csv", "RESULTADOS_Y_ESTADISTICA.csv"),
        # 6. AUDITORIA_FINAL.md
        (repo_root / "AUDITORIA_FINAL.md", "AUDITORIA_FINAL.md"),
    ]

    # 7. REPRODUCIBILIDAD/
    for p in auto_dir.rglob("*"):
        if p.is_file() and not p.name.endswith(".pyc") and "__pycache__" not in str(p):
            rel = p.relative_to(auto_dir)
            items_to_pack.append((p, f"REPRODUCIBILIDAD/{rel}"))

    # Logs reales en REPRODUCIBILIDAD/
    items_to_pack.append((repo_root / "AUTONOMOUS_REPRODUCTION_LOG.txt", "REPRODUCIBILIDAD/AUTONOMOUS_REPRODUCTION_LOG.txt"))
    items_to_pack.append((repo_root / "AUTONOMOUS_TESTS_LOG.txt", "REPRODUCIBILIDAD/AUTONOMOUS_TESTS_LOG.txt"))

    # 8. FIGURAS/
    for fig_name in [
        "fig1_tradeoff_cost_coverage.png",
        "fig2_risk_vs_coverage.png",
        "fig3_policy_comparison_n118_n240.png",
        "fig4_ablations_analysis.png"
    ]:
        items_to_pack.append((fig_dir / fig_name, f"FIGURAS/{fig_name}"))

    print(f"Empaquetando {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for src, arc in items_to_pack:
            if not src.exists():
                raise FileNotFoundError(f"Archivo requerido no existe: {src}")
            zf.write(src, arc)
            print(f"  + {arc} ({src.stat().st_size} bytes)")

    sha256 = get_sha256(zip_path)
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"\nENTREGABLE UNICO CREADO EXITOSAMENTE:")
    print(f"Ruta: {zip_path}")
    print(f"Tamano: {size_mb:.2f} MB ({zip_path.stat().st_size} bytes)")
    print(f"SHA-256: {sha256}")

    hash_file = repo_root / "RAEA_PHISH_EVIDENCIA_EXTERNA_FINAL.zip.sha256"
    hash_file.write_text(f"{sha256}  {zip_path.name}\n", encoding="utf-8")
    print(f"Hash guardado en: {hash_file.name}")

if __name__ == "__main__":
    main()
