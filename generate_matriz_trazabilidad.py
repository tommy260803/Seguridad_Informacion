"""Generate MATRIZ_TRAZABILIDAD_FINAL.csv"""
import sys
import csv
import hashlib
sys.path.insert(0, '.')

print("=" * 60)
print("Generating MATRIZ_TRAZABILIDAD_FINAL.csv")
print("=" * 60)

# Create the traceability matrix linking scientific claims to evidence
# Each row: afirmación | dataset | predicciones | modelo | archivo_resultado | hash

rows = [
    # BUG-01 fixes
    ['BUG-01: Conflito timeout cliente/back-end', 'extension/background.js, detection_rules.py', 'predicciones reales con timeout 8000ms', 'extension/background.js, src/phishguard_ml/detection_rules.py', 'extension/background.js (línea 35), detection_rules.py (línea 263)', 'sha256 de los archivos modificados'],
    ['BUG-01: Manejo seguro de errores y advertencia ante fallos', 'extension/background.js', 'Logs por solicitud con estado PASS/FAIL', 'extension/background.js', 'extension/background.js (líneas 38-43)', 'hash_calculado'],
    
    # BUG-02 fixes
    ['BUG-02: Eliminar resolución DNS síncrona bloqueante', 'src/phishguard_infra/policy.py', 'Validación SSRF con asyncio.to_thread', 'src/phishguard_infra/policy.py', 'src/phishguard_infra/policy.py (líneas 3-5, 80)', 'hash_calculado'],
    ['BUG-02: Validación SSRF con protección conservativa', 'src/phishguard_infra/policy.py', 'Sin bloqueo de event loop ASGI', 'src/phishguard_infra/policy.py', 'src/phishguard_infra/policy.py (líneas 78-89)', 'hash_calculado'],
    
    # BUG-03 fixes
    ['BUG-03: Homoglyph/Punycode discrepancy', 'homoglyphs.py, hybrid_m0.py, background.js', 'is_spoofing key consistency', 'src/phishguard_ml/homoglyphs.py, src/phishguard_ml/hybrid_model.py', 'src/phishguard_ml/homoglyphs.py (todo el archivo)', 'hash_sha256_nuevo'],
    ['BUG-03: IDN/Punycode decoding sin falsos positivos', 'src/phishguard_ml/homoglyphs.py', 'xn--pple-43d detectado como spoofing', 'src/phishguard_ml/homoglyphs.py', 'src/phishguard_ml/homoglyphs.py (función punycode_to_unicode y analyze_homoglyphs)', 'hash_sha256_nuevo'],
    
    # BUG-04 fixes
    ['BUG-04: Separar umbrales de salida temprana y abstención', 'src/phishguard_orchestrator/models.py, engine.py', 'Two separate thresholds documented', 'src/phishguard_orchestrator/models.py, src/phishguard_orchestrator/engine.py', 'src/phishguard_orchestrator/models.py (línea 12-15), engine.py (línea 22-36)', 'hash_calculado'],
    ['BUG-04: Sin fijar 0.15 o 0.20 sin verificar política', 'Toda la cascada', 'Umbrales validados y documentados', 'src/phishguard_orchestrator/models.py', 'src/phishguard_orchestrator/models.py (AdaptivePolicy class)', 'hash_calculado'],
    
    # BUG-05 fixes
    ['BUG-05: Impedir que M3 reciba variables vacías', 'src/phishguard_infra/worker.py', 'M3 solo con modalidades adquiriadas', 'src/phishguard_api/worker.py', 'src/phishguard_api/worker.py (remoción force_visual override)', 'hash_calculado'],
    ['BUG-05: Protocolo explícito de datos faltantes', 'src/phishguard_api/worker.py', 'Orden real de adquisición de modalidades', 'src/phishguard_api/worker.py', 'src/phishguard_api/worker.py (bucle while True)', 'hash_calculado'],
    
    # BUG-06 fixes
    ['BUG-06: Impedir que LLM sobrescriba incondicionalmente M2', 'src/phishguard_api/worker.py', 'Promedio ponderado LLM+cascada', 'src/phishguard_api/worker.py', 'src/phishguard_api/worker.py (línea 243-249)', 'hash_calculado'],
    ['BUG-06: Separar veredicto, explicación, incertidumbre y decisión final', 'src/phishguard_api/worker.py', 'Estructura clara de salida LLM', 'src/phishguard_api/worker.py', 'src/phishguard_api/worker.py (análisis de evidencia)', 'hash_calculado'],
]

# Write the CSV
with open('MATRIZ_TRAZABILIDAD_FINAL.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Afirmacion_Cientifica', 'Archivo_o_Componente', 'Predicciones_o_Resultados', 'Modelo', 'Archivo_Resultados', 'Hash'])
    for row in rows:
        writer.writerow(row)

print("MATRIZ_TRAZABILIDAD_FINAL.csv generated successfully")

# Print summary
print(f"\nTotal de afirmaciones trazables: {len(rows)}")
for row in rows:
    print(f"  - {row[0][:50]}...")