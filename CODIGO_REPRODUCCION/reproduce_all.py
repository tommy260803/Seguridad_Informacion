"""
Script maestro de reproduccion integral de resultados de RAEA-Phish.
Ejecuta la verificacion de politicas, generacion de figuras y suite de pruebas de consistencia.
"""
import sys
import subprocess
from pathlib import Path

def main():
    repo_root = Path(__file__).resolve().parent.parent
    print(f"=== REPRODUCIENDO RESULTADOS RAEA-PHISH EN {repo_root} ===")

    # 1. Ejecutar raea_final_verification.py
    print("\n[1/3] Ejecutando scripts/raea_final_verification.py...")
    cmd1 = [sys.executable, str(repo_root / "scripts" / "raea_final_verification.py")]
    res1 = subprocess.run(cmd1, capture_output=True, text=True, cwd=str(repo_root))
    if res1.returncode != 0:
        print("ERROR en paso 1:")
        print(res1.stderr)
        sys.exit(1)
    print("Paso 1 completado exitosamente.")

    # 2. Generar figuras
    print("\n[2/3] Generando figuras cientificas...")
    cmd2 = [sys.executable, str(repo_root / "scripts" / "generate_scientific_figures.py")]
    res2 = subprocess.run(cmd2, capture_output=True, text=True, cwd=str(repo_root))
    if res2.returncode != 0:
        print("ERROR en paso 2:")
        print(res2.stderr)
        sys.exit(1)
    print("Paso 2 completado exitosamente.")

    # 3. Ejecutar pruebas de consistencia
    print("\n[3/3] Ejecutando pruebas unitarias de reproduccion...")
    cmd3 = [sys.executable, "-m", "pytest", str(repo_root / "CODIGO_REPRODUCCION" / "test_reproduction_consistency.py"), "-v"]
    res3 = subprocess.run(cmd3, capture_output=True, text=True, cwd=str(repo_root))
    if res3.returncode != 0:
        print("ERROR en paso 3:")
        print(res3.stdout)
        print(res3.stderr)
        sys.exit(1)
    print("Paso 3 completado exitosamente.")
    print(res3.stdout)

    print("\n=== TODAS LAS PRUEBAS Y REPRODUCCIONES FINALIZADAS CON EXITO ===")

if __name__ == "__main__":
    main()
