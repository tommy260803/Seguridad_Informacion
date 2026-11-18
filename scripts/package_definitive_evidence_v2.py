"""
Empaqueta todos los artefactos de la Fase 1, Fase 2 y Fase 3 en:
RAEA_PHISH_EVIDENCIA_CIENTIFICA_DEFINITIVA_V2.zip
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
    zip_path = repo_root / "RAEA_PHISH_EVIDENCIA_CIENTIFICA_DEFINITIVA_V2.zip"
    
    components = []
    
    # Informes maestros
    components.append((repo_root / "PROTOCOLO_CONGELADO.md", "PROTOCOLO_CONGELADO.md"))
    components.append((repo_root / "INFORME_EVALUACION_INDEPENDIENTE.md", "INFORME_EVALUACION_INDEPENDIENTE.md"))
    components.append((repo_root / "RESUMEN_CIENTIFICO_DEFINITIVO.md", "RESUMEN_CIENTIFICO_DEFINITIVO.md"))
    components.append((repo_root / "AUDITORIA_FINAL.md", "AUDITORIA_FINAL.md"))
    components.append((repo_root / "AUTONOMOUS_REPRODUCTION_LOG.txt", "AUTONOMOUS_REPRODUCTION_LOG.txt"))
    components.append((repo_root / "AUTONOMOUS_TESTS_LOG.txt", "AUTONOMOUS_TESTS_LOG.txt"))
    
    # Suite autonoma
    auto_dir = repo_root / "autonomous_reproduction_suite"
    for p in auto_dir.rglob("*"):
        if p.is_file() and not p.name.endswith(".pyc") and "__pycache__" not in str(p):
            arc = f"REPRODUCIBILIDAD_AUTONOMA/{p.relative_to(auto_dir)}"
            components.append((p, arc))
            
    # Retrospectiva N=118
    retro_dir = repo_root / "artifacts" / "raea_final"
    for name in ["RESULTADOS_DEFINITIVOS.csv", "PREDICCIONES_INDIVIDUALES.csv", "ABLACIONES_DEFINITIVAS.csv", "ESTADISTICA_DEFINITIVA.csv", "COHORTE_Y_ETIQUETAS.csv"]:
        components.append((retro_dir / name, f"EVIDENCIA_RETROSPECTIVA_N118/{name}"))
    for fig in (retro_dir / "FIGURAS").glob("*.png"):
        components.append((fig, f"EVIDENCIA_RETROSPECTIVA_N118/FIGURAS/{fig.name}"))
        
    # Independiente N=240
    indep_dir = repo_root / "artifacts" / "raea_independent_n240"
    for name in ["COHORTE_INDEPENDIENTE_N240_MANIFIESTO.csv", "PREDICCIONES_INDEPENDIENTES_N240.csv", "RESULTADOS_INDEPENDIENTES_N240.csv", "ABLACIONES_INDEPENDIENTES_N240.csv", "ESTADISTICA_INDEPENDIENTE_N240.csv"]:
        components.append((indep_dir / name, f"EVIDENCIA_INDEPENDIENTE_N240/{name}"))
    for fig in (indep_dir / "FIGURAS").glob("*.png"):
        components.append((fig, f"EVIDENCIA_INDEPENDIENTE_N240/FIGURAS/{fig.name}"))
        
    print(f"Empaquetando {zip_path.name}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for src, arc in components:
            if not src.exists():
                raise FileNotFoundError(f"Falta archivo: {src}")
            zf.write(src, arc)
            print(f"  + {arc}")
            
    sha256 = get_sha256(zip_path)
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"\nPAQUETE CREADO:")
    print(f"Ruta: {zip_path}")
    print(f"Tamano: {size_mb:.2f} MB ({zip_path.stat().st_size} bytes)")
    print(f"SHA-256: {sha256}")
    
    hash_file = repo_root / "RAEA_PHISH_EVIDENCIA_CIENTIFICA_DEFINITIVA_V2.zip.sha256"
    hash_file.write_text(f"{sha256}  {zip_path.name}\n", encoding="utf-8")
    print(f"Hash guardado en: {hash_file.name}")

if __name__ == "__main__":
    main()
