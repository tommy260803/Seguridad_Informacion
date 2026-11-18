# INSTRUCCIONES DE REPRODUCCIÓN CIENTÍFICA: RAEA-PHISH

Este directorio contiene los scripts y configuraciones mínimos necesarios para reproducir de forma determinista la totalidad de los resultados, ablaciones, matrices y contrastes estadísticos del paquete `RAEA_PHISH_EVIDENCIA_FINAL_VERIFICADA.zip`.

---

## 1. REQUISITOS DEL ENTORNO
- **Python:** 3.12 (o superior)
- **Librerías principales:** `numpy`, `pandas`, `scipy`, `scikit-learn`, `joblib`, `pytest`
- **Modelos base congelados:** En `artifacts/` (congelados en commit `058169a99786a42203d7db27d5da994b6ceb61c9`)

---

## 2. PIPELINE DE REPRODUCCIÓN PASO A PASO

### Paso 1: Auditoría de Etiquetas y Población Experimental
Clasifica las 600 URLs de la Cohorte 2 según su procedencia verificable y separa el malware del phishing web:
```bash
python scripts/raea_label_audit.py
```
*Genera:* `artifacts/raea_final/DATOS_Y_ETIQUETAS.csv` y `label_audit_summary.json`.

### Paso 2: Ejecución del Replay Experimental y Pruebas Estadísticas
Ejecuta todas las políticas (B0 a B6), comparadores selectivos (B5_chow, B5_cov), variantes de ablación (A1 a A6) y remuestreos Bootstrap sobre las tres poblaciones de análisis:
```bash
python scripts/raea_final_verification.py
```
*Genera:*
- `artifacts/raea_final/PREDICCIONES_Y_DECISIONES.csv` (predicciones fila por fila para cada URL y política)
- `artifacts/raea_final/RESULTADOS_COMPARATIVOS.csv` (métricas predictivas, selectivas y operativas)
- `artifacts/raea_final/ABLACIONES_VERIFICADAS.csv` (verificación de desactivación de componentes)
- `artifacts/raea_final/ESTADISTICA_Y_RIESGO.csv` (contrastes pareados, CIs y barridos de costes)
- `artifacts/raea_final/run_metadata.json` (hashes SHA-256 de entradas y commit base)

### Paso 3: Validación Automática de Consistencia
Ejecuta la suite de pruebas de integridad:
```bash
pytest CODIGO_REPRODUCCION/test_reproduction_consistency.py -v
```

### Paso 4: Empaquetado y Verificación Criptográfica
Genera el paquete final consolidado con sus sumas de verificación SHA-256:
```bash
python scripts/package_final_verified_evidence.py
```
*Genera:* `RAEA_PHISH_EVIDENCIA_FINAL_VERIFICADA.zip` en la raíz del repositorio.
