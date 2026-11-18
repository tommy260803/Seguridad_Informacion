"""
Empaqueta el entregable único obligatorio:
RAEA_PHISH_CIERRE_CIENTIFICO.zip
con exactamente los 8 componentes especificados.
"""
from __future__ import annotations
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
    zip_path = repo_root / "RAEA_PHISH_CIERRE_CIENTIFICO.zip"
    
    # 8 componentes obligatorios
    c1_resumen = repo_root / "RESUMEN_CIENTIFICO_FINAL.md"
    c2_audit_ext = repo_root / "AUDITORIA_COHORTE_EXTERNA.csv"
    c3_manifiesto = repo_root / "MANIFIESTO_INDEPENDENCIA.md"
    c4_res_reconciliados = repo_root / "RESULTADOS_RECONCILIADOS.csv"
    c5_pred_auditadas = repo_root / "PREDICCIONES_AUDITADAS.csv"
    c6_audit_final = repo_root / "AUDITORIA_FINAL.md"
    c7_reproducibilidad_dir = repo_root / "autonomous_reproduction_suite"
    c8_figuras_dir = repo_root / "FIGURAS"

    for c in [c1_resumen, c2_audit_ext, c3_manifiesto, c4_res_reconciliados, c5_pred_auditadas, c6_audit_final, c7_reproducibilidad_dir, c8_figuras_dir]:
        if not c.exists():
            raise FileNotFoundError(f"Componente obligatorio no encontrado: {c}")

    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        # 1. RESUMEN_CIENTIFICO_FINAL.md
        zf.write(c1_resumen, arcname="RESUMEN_CIENTIFICO_FINAL.md")
        # 2. AUDITORIA_COHORTE_EXTERNA.csv
        zf.write(c2_audit_ext, arcname="AUDITORIA_COHORTE_EXTERNA.csv")
        # 3. MANIFIESTO_INDEPENDENCIA.md
        zf.write(c3_manifiesto, arcname="MANIFIESTO_INDEPENDENCIA.md")
        # 4. RESULTADOS_RECONCILIADOS.csv
        zf.write(c4_res_reconciliados, arcname="RESULTADOS_RECONCILIADOS.csv")
        # 5. PREDICCIONES_AUDITADAS.csv
        zf.write(c5_pred_auditadas, arcname="PREDICCIONES_AUDITADAS.csv")
        # 6. AUDITORIA_FINAL.md
        zf.write(c6_audit_final, arcname="AUDITORIA_FINAL.md")
        
        # 7. REPRODUCIBILIDAD/
        for p in sorted(c7_reproducibilidad_dir.rglob("*")):
            if p.is_file() and not "__pycache__" in p.parts and not "output" in p.parts:
                rel = p.relative_to(c7_reproducibilidad_dir).as_posix()
                arc = f"REPRODUCIBILIDAD/{rel}"
                zf.write(p, arcname=arc)
                
        # 8. FIGURAS/
        for p in sorted(c8_figuras_dir.glob("*.png")):
            zf.write(p, arcname=f"FIGURAS/{p.name}")

    sha256_val = get_sha256(zip_path)
    sha_file = repo_root / "RAEA_PHISH_CIERRE_CIENTIFICO.zip.sha256"
    sha_file.write_text(f"{sha256_val}  RAEA_PHISH_CIERRE_CIENTIFICO.zip\n", encoding="utf-8")

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print("=" * 78)
    print("PAQUETE CIENTÍFICO FINAL GENERADO EXITOSAMENTE:")
    print(f"  Ruta:    {zip_path}")
    print(f"  Tamaño:  {size_mb:.2f} MB ({zip_path.stat().st_size:,} bytes)")
    print(f"  SHA-256: {sha256_val}")
    print("=" * 78)
    print("Contenido del paquete:")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            print(f"  - {info.filename:50s} ({info.file_size:,} bytes)")

if __name__ == "__main__":
    main()
