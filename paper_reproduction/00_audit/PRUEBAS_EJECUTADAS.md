# REGISTRO DETALLADO DE PRUEBAS EJECUTADAS — PHISHPE / PHISHGUARD PRO

**Fecha de ejecución:** 2026-10-15  
**Auditor:** Ingeniero de Aseguramiento de Calidad de Software, MLOps y Auditor de Reproducibilidad  
**Repositorio:** `D:\Proyects\Seguridad_Informacion`  
**Entorno de ejecución:** Windows 11 Pro 64-bit · Python 3.12.10 · Pytest 9.0.3  
**Directiva de seguridad operacional:** *Ninguna URL maliciosa fue consultada o detonada directamente en el equipo anfitrión durante esta auditoría.*

---

## 1. Resumen Consolidado de Baterías de Prueba

| Batería / Script Ejecutado | Total Pruebas / Comprobaciones | PASS | FAIL | SKIP / NOT_RUN | Veredicto |
|---|---:|---:|---:|---:|---|
| **1. Suite Automatizada Pytest (`tests/`)** | 186 | 186 | 0 | 0 | **PASS** |
| **2. Revalidación Offline Freeze #5 (`phase2n`)** | 11 | 11 | 0 | 0 | **PASS** |
| **3. Verificación de Regresiones Críticas (`phase2g`)** | 4 bloques (15 casos) | 4 | 0 | 0 | **PASS** |
| **4. Consistencia de Estadísticas Pareadas (`phase2e`)** | 28 comprobaciones | 28 | 0 | 0 | **PASS** |
| **5. Consistencia Multimodal de Métricas (`verify_audit`)** | 48 comprobaciones | 48 | 0 | 0 | **PASS** |
| **6. Integridad de Entregables y ZIP (`verify_deliverables`)**| 16 comprobaciones | 16 | 0 | 0 | **PASS** |
| **7. Escaneo Preventivo de Secretos (`_secret_scan`)** | 319 archivos | 319 | 0 | 0 | **PASS** |
| **8. Integridad de Manuscrito Word (`verify_article`)** | 24 comprobaciones | 0 | 24 | 0 | **FAIL (Documentado)**|

---

## 2. Detalle de Ejecución por Batería

### Batería 1: Suite Completa de Pruebas Unitarias y de Regresión (`pytest`)
* **Comando ejecutado:** `pytest`
* **Salida de ejecución:**
  ```text
  ........................................................................ [ 38%]
  ........................................................................ [ 77%]
  ..........................................                               [100%]
  ============================== warnings summary ===============================
  C:\Users\User\AppData\Local\Programs\Python\Python312\Lib\site-packages\starlette\testclient.py:53:
    DeprecationWarning: The anyio.abc.BlockingPortal alias is deprecated, use anyio.from_thread.BlockingPortal instead.
  186 passed, 1 warning in 14.30s
  ```
* **Desglose de pruebas por componente:**
  - `tests/test_corrections_phase2.py`: 47 pruebas de regresión cubriendo los 8 defectos (BUG-01 a BUG-08) y las condiciones C-1 a C-5:
    * `TestBug01TimeoutBudget` (3 casos): Presupuesto de 8000 ms en extensión y backend.
    * `TestBug02AsyncDns` (4 casos): Ejecución de DNS fuera del bucle de eventos (`asyncio.to_thread`).
    * `TestBug03Punycode` (12 casos): Decodificación etiqueta a etiqueta de Punycode `xn--` y anti-spoofing.
    * `TestBug04SeparateThresholds` (5 casos): Separación entre umbral de incertidumbre y de abstención.
    * `TestBug05NoForcedVisualStage` (2 casos): Eliminación de forzado de visión y override espurio.
    * `TestBug06LlmBlend` (3 casos): Mezcla lineal $0.7\cdot p_{\text{cascada}} + 0.3\cdot p_{\text{LLM}}$.
    * `TestBug07StripWww` (3 casos): Descuento del prefijo `www.` para eliminar el atajo de aprendizaje.
    * `TestBug08LevenshteinDp` (15 casos): Algoritmo DP fila móvil comparado contra matriz 2D naive.
  - `tests/test_homoglyphs.py`: Pruebas de confusables visuales, caracteres cirílicos/griegos y esqueletos.
  - `tests/test_content_analyzer.py`: Extracción de formularios, inputs de contraseña y scripts en DOM HTML.
  - `tests/test_infra_policy.py`: Mitigación de SSRF, bloqueo de IPs privadas y rangos reservados.
  - `tests/test_ml_training.py`: Entrenamiento, balanceo y calibración de clasificadores.
  - `tests/test_explanation.py`: Generación de factores explicables para el usuario final.
* **Resultado:** **PASS (186/186 pruebas superadas al 100%)**.

---

### Batería 2: Revalidación Offline bajo Freeze #5 (`phase2n_revalidate_offline.py`)
* **Comando ejecutado:** `python scripts/phase2n_revalidate_offline.py`
* **Salida de ejecución:**
  ```text
  Loading M0 model from artifacts\url-baseline-0.2.0\model.joblib
  === BLOQUE A: nivel URL sobre la cohorte2 (N=1200) ===
  [ReputationEngine] Tranco Top 1M indexado con éxito: 1,000,000 dominios en memoria.
    M0 original  F1=0.8829 FPR=0.0333
    M0 normalizado F1=0.8707 FPR=0.0333
    Config A F1=0.8593 | Config C F1=0.8550
  === BLOQUE D: recomputación interna desde predicciones congeladas ===
  === BLOQUE E: experimento pareado www. vs sin www. ===
  {
    "n_urls": 600,
    "n_unique_samples": 300,
    "FPR_M0_original_on_www_legit": 1.0,
    "FPR_M0_normalizado_on_www_legit": 0.053333,
    "paired_flips": {"original_www_vs_nonwww": 170, "normalizado_www_vs_nonwww": 0, "n_pairs": 300}
  }
  {
    "n_checks": 11,
    "n_pass": 11,
    "n_fail": 0,
    "dictamen": "PASS"
  }
  ```
* **Comprobaciones de integridad verificadas:**
  1. `verify_freeze()` ok=True sobre el código actual.
  2. Invarianza de pesos de modelos entre Freeze #3 y #5 (byte-idénticos).
  3. Re-cálculo de `url_level_predictions.csv` byte a byte idéntico al congelado.
  4. Métricas de cohorte externa reproducidas al 100%.
  5. 0 cambios en artefactos canónicos de `eval/` durante la corrida.
* **Resultado:** **PASS (11/11 verificaciones aprobadas)**.

---

### Batería 3: Regresiones Manuales Auditadas (`phase2g_verify_manual_audit_regressions.py`)
* **Comando ejecutado:** `python scripts/phase2g_verify_manual_audit_regressions.py`
* **Resultados específicos:**
  - **BUG-03 (Punycode):** `analyze_homoglyphs('www.xn--pple-43d.com', 'xn--pple-43d.com')` $\to$ `is_spoofing: True`, `homoglyph_brand_spoofing_detected: True`, esqueleto: `'www.apple.com'`, objetivo: `'apple'`. Controles negativos (`apple.com`, `google.com`, `muenchen.de`, `espol.edu.ec`) devuelven todos `is_spoofing: False`.
  - **BUG-08 (Acortadores):** Dominios cortos de acortadores (`t.ly`, `t.is`, `s.id`, `is.gd`, `ow.ly`) devuelven todos `is_spoofing: False`, eliminando la falsa alarma por longitud.
  - **BUG-04 (Umbral de abstención):** Para una muestra con probabilidad $p = 0.85$ y entropía $H = 0.6098$:
    * Con $\tau_{\text{abst}} = 0.01 \implies \text{action} = \text{"abstain"}$.
    * Con $\tau_{\text{abst}} = 0.20 \implies \text{action} = \text{"abstain"}$.
    * Con $\tau_{\text{abst}} = 0.99 \implies \text{action} = \text{"decide"}$.
    * Comprobado: el umbral de abstención gobierna efectivamente la decisión del orquestador.
* **Resultado:** **PASS (`overall_PASS: true`)**.

---

### Batería 4: Verificación de Estadísticas Pareadas Históricas (`phase2e_verify_historical_stats.py`)
* **Comando ejecutado:** `python scripts/phase2e_verify_historical_stats.py`
* **Salida de ejecución:**
  ```text
  {
    "n_rows_published": 14,
    "n_match": 14,
    "n_mismatch": 0,
    "n_table_rows_checked": 14,
    "n_table_mismatch": 0,
    "dictamen": "PASS: todas las filas del CSV publicado son reproducibles desde los predictions.csv congelados y las 14 filas de las tablas del informe 07 coinciden con el CSV canónico"
  }
  ```
* **Resultado:** **PASS (14/14 filas del CSV canónico y 14/14 filas de informe coincidentes)**.

---

### Batería 5: Consistencia Global de Métricas y Evidencias (`verify_audit_report_consistency.py`)
* **Comando ejecutado:** `python scripts/verify_audit_report_consistency.py`
* **Salida de ejecución:**
  - Recuento de corpus: 176,201 total (99,994 legítimas, 76,207 phishing) $\to$ **OK**.
  - Partición `host_unseen` Complete-Case: 691 URLs $\to$ **OK**.
  - Métricas M0 a M5: F1 M0 (0.8658), M1 (0.9252), M2 (0.9315), M3 (0.9286), M4 (0.9248), M4-Fixed (0.9029), M5 (0.9538 con Precisión 1.0000) $\to$ **OK**.
  - Métricas CDP auténticas N=83: F1 (0.8966), Recall (0.9286), ROC-AUC (0.9789) $\to$ **OK**.
  - Comparaciones McNemar pareadas (M0 vs M1, M0 vs M2, M0 vs M3, M0 vs M4, M0 vs M5) $\to$ **OK**.
  - Pruebas de robustez ante 6 familias adversariales $\to$ **OK**.
  - Telemetría de hardware (i5-13600K, 15.78 GB RAM) y latencias P50 de pared $\to$ **OK**.
  - Filtro Bloom Tranco (53,345 elementos, 93.62 KB, 4.6 $\mu$s) y caché de extensión (hit rate: 92.30%) $\to$ **OK**.
* **Resultado:** **SUCCESS: 100% of verified figures, sample counts, metrics, latencies match disk evidence**.

---

### Batería 6: Integridad de Entregables y Paquete ZIP (`verify_deliverables.py`)
* **Comando ejecutado:** `python verify_deliverables.py`
* **Salida de verificación:**
  - Verificados en disco: `INFORME_FINAL_PHISHPE_CORREGIDO.md`, `COMPARACION_ANTES_DESPUES.csv`, `MATRIZ_TRAZABILIDAD_FINAL.csv`, `VALIDACION_FINAL_AUTOMATICA.json`, `LIMITACIONES_RESTANTES.md`, `RESUMEN_DEFINITIVO_PARA_ARTICULO.md`, `evidencia_phishpe_definitiva.zip`.
  - Hash SHA-256 del ZIP recalculado: `369e193589c20fa637d5373eb54dc89f519df87753370e840f0510df2aba04af` (coincide exactamente con `evidencia_phishpe_definitiva.sha256`).
* **Resultado:** **PASS**.

---

### Batería 7: Escaneo Preventivo de Secretos a Árbol Completo (`_secret_scan_before_commit.py`)
* **Comando ejecutado:** `python scripts/_secret_scan_before_commit.py`
* **Salida de ejecución:**
  - Total archivos escaneados: 319 (rastreados + no ignorados).
  - Secretos no documentados: **0**.
  - Hallazgos preexistentes documentados: 1 (`extension.pem`, clave de firma de extensión, documentada en `AUDITORIA_SEGURIDAD.md` y `LIMITACIONES_RESTANTES.md`).
* **Resultado:** **PASS (0 secretos sin documentar, exit code 0)**.

---

### Batería 8: Comprobación de Integridad de Manuscrito Word (`verify_article_integrity.py`)
* **Comando ejecutado:** `python scripts/verify_article_integrity.py`
* **Salida de ejecución:**
  ```text
  [FAIL] Manuscript PhishGuard_Article_APA7.docx still contains legacy synthetic string: '1.52e-12'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '176,201'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '5,612'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '691'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '0.8658'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '0.9286'
  [FAIL] Manuscript PhishGuard_Article_APA7.docx is missing required real evidence string: '0.9538'
  [FAIL] Manuscript PhishPe_Article_APA7.docx still contains legacy synthetic string: 'N = 2,000'
  [FAIL] Manuscript PhishPe_Article_APA7.docx still contains legacy synthetic string: '1,250.0 ms'
  ```
* **Diagnóstico y justificación:**
  - Los archivos Word `.docx` son versiones preliminares redactadas con cifras sintéticas aproximadas antes de la ejecución de las fases experimentales definitivas.
  - El equipo auditor previo conservó deliberadamente los documentos Word sin editar (`git diff ceb0c9e..HEAD --stat -- *Article*.docx` vacío) para no realizar cambios editoriales no autorizados.
* **Resultado:** **FAIL (Previsto y controlado: constituye la tarea central de la Fase 1 del plan de ejecución)**.
