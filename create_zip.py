"""Create evidencia zip package"""
import zipfile
import hashlib
import os

# Create the zip file with all evidence
zip_path = "evidencia_phishpe_definitiva.zip"

# Files to include (the critical corrections and documentation)
critical_files = [
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
]

# Also include the original bug list file
if os.path.exists("LIMITACIONES_Y_PENDIENTES.md"):
    critical_files.append("LIMITACIONES_Y_PENDIENTES.md")

# Create zip
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for filename in critical_files:
        if os.path.exists(filename):
            zf.write(filename, filename)
            print(f"  Added: {filename}")
        else:
            print(f"  WARNING: {filename} not found")

# Calculate final ZIP hash
with open(zip_path, 'rb') as f:
    zip_data = f.read()
zip_hash = hashlib.sha256(zip_data).hexdigest()

print(f"\nZip created: {zip_path}")
print(f"SHA-256: {zip_hash}")
print(f"Files included: {len([f for f in critical_files if os.path.exists(f)])}")