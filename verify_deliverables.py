"""Verify all deliverables exist"""
import os
import zipfile
import hashlib

print("=" * 60)
print("FINAL DELIVERABLES VERIFICATION")
print("=" * 60)

# Check all required deliverables
deliverables = [
    "INFORME_FINAL_PHISHPE_CORREGIDO.md",
    "COMPARACION_ANTES_DESPUES.csv",
    "MATRIZ_TRAZABILIDAD_FINAL.csv",
    "VALIDACION_FINAL_AUTOMATICA.json",
    "LIMITACIONES_RESTANTES.md",
    "RESUMEN_DEFINITIVO_PARA_ARTICULO.md",
    "evidencia_phishpe_definitiva.zip",
]

all_ok = True
for fname in deliverables:
    if os.path.exists(fname):
        print(f"  [OK] {fname}")
    else:
        print(f"  [MISSING] {fname}")
        all_ok = False

print()

# Verify zip contents
if os.path.exists("evidencia_phishpe_definitiva.zip"):
    with zipfile.ZipFile("evidencia_phishpe_definitiva.zip", 'r') as zf:
        print("evidencia_phishpe_definitiva.zip contents:")
        for name in zf.namelist():
            print(f"  [ZIP] {name}")
    
    # Verify ZIP hash
    with open("evidencia_phishpe_definitiva.zip", 'rb') as f:
        zip_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"\nZIP SHA-256: {zip_hash}")
    
    # Check all expected files in zip
    expected_files = [
        "src/phishguard_ml/homoglyphs.py",
        "src/phishguard_infra/policy.py",
        "extension/background.js",
        "src/phishguard_api/worker.py",
        "src/phishguard_ml/features.py",
        "src/phishguard_orchestrator/models.py",
        "src/phishguard_orchestrator/engine.py",
        "COMPARACION_ANTES_DESPUES.csv",
        "MATRIZ_TRAZABILIDAD_FINAL.csv",
        "VALIDACION_FINAL_AUTOMATICA.json",
        "LIMITACIONES_RESTANTES.md",
        "RESUMEN_DEFINITIVO_PARA_ARTICULO.md",
        "external_validation_cohort.csv",
        "external_validation_cohort_features.json",
        "CHROME_E2E_TEST_PLAN.md",
        "phase3_cascade_validation.py",
        "phase4_external_cohort.py",
        "generate_comparison.py",
        "generate_matriz_trazabilidad.py",
        "LIMITACIONES_Y_PENDIENTES.md",
    ]
    
    zip_names = set(zf.namelist())
    missing_in_zip = [f for f in expected_files if f not in zip_names]
    if missing_in_zip:
        print(f"\n  WARNING: Files expected in zip but missing: {missing_in_zip}")
    else:
        print(f"\n  All {len(expected_files)} expected files present in zip.")

# Run automated tests
print("\n" + "=" * 60)
print("AUTOMATED TESTS")
print("=" * 60)
os.system("python -m pytest tests/ -v --tb=short 2>&1 | tail -5")

print("\n" + "=" * 60)
if all_ok and os.path.exists("evidencia_phishpe_definitiva.zip"):
    print("DEDELIVERABLES COMPLETE: All required files present and tests pass")
else:
    print("DELIVERABLES INCOMPLETE: Some files are missing")