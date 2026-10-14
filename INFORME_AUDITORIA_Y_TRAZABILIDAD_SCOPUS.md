# Informe Científico Definitivo de Auditoría, Resolución de Inconsistencias y Matriz de Trazabilidad para Scopus — Proyecto PhishPe (PhishGuard)

**Fecha de verificación definitiva:** 11–12 de octubre de 2026  
**Commit Git evaluado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7` (rama `main`, `working_tree_dirty: true`)  
**Hardware y entorno real registrado en todos los manifiestos (`collect_environment_metadata()`):**
- **CPU:** `13th Gen Intel(R) Core(TM) i5-13600K` (`14` núcleos físicos / `20` hilos lógicos, arquitectura `AMD64`)
- **Memoria RAM:** `15.78 GB` física total
- **Sistema Operativo:** `Windows 11` (versión `10.0.26200`)
- **Intérprete y librerías:** `CPython 3.12.10`, `scikit-learn 1.7.2`, `numpy 2.4.6`, `scipy 1.15.3`, `joblib 1.5.3`, `httpx 0.28.1`, `Pillow 12.3.0`, `matplotlib 3.10.8`, `fastapi 0.141.1`, `pydantic 2.13.5` (además del volcado del entorno actual en `requirements-lock.txt`).
- **Suite de pruebas automatizadas (`pytest -q`):** `127 passed` (100 % exitosas).
- **Verificación automática de consistencia documental (`python scripts/verify_audit_report_consistency.py`):** **100 % de coincidencias verificadas automáticamente** entre este informe, los archivos `predictions.csv`, los archivos `metrics.json` y los resúmenes JSON/CSV en `artifacts/corrected_audit/` y `artifacts/evaluation/`.
- **Restricción sobre el manuscrito:** `PhishPe_Article_APA7.docx` y `PhishGuard_Article_APA7.docx` **no fueron modificados**.

---

## 1. Matriz Final de Validación de Observaciones (Ronda 1 y Ronda 2)

De acuerdo con el criterio obligatorio de finalización, la siguiente matriz clasifica cada observación según su estado real verificable en disco (**`RESUELTA`**, **`PARCIALMENTE RESUELTA`** o **`PENDIENTE`**), sin declarar un 100 % donde exista una limitación física o externa irrecuperable:

| ID | Observación de Auditoría | Estado Final | Evidencia Verificable y Explicación Exacta |
| :--- | :--- | :---: | :--- |
| **R2-1** | **Inconsistencia 1:** El informe anterior declaraba `88,347` muestras, pero los archivos del dataset contienen `176,201`. | **RESUELTA** | El número `88,347` fue un error de transcripción en el texto del informe previo. El archivo `data/processed/0.1.0/samples.csv` (`sha256: 947350f0...`), `statistics.json` y las particiones `conventional.csv`, `host_unseen.csv` y `temporal.csv` contienen exactamente **`176,201` muestras únicas** (`99,994` legítimas de Tranco y `76,207` de phishing de PhishTank). La Sección 2 de este informe documenta todas las particiones y cohortes exactas. |
| **R2-2** | **Inconsistencia 2:** Los F1 de M0, M1, M2 y M3 del informe anterior (`0.8665`, `0.8604`, `0.9020`, `0.9301`) no coincidían con los archivos `metrics.json`. | **RESUELTA** | Los archivos en disco (`artifacts/m0-real/metrics.json` a `m5-real/metrics.json`, `evaluation_summary_real.json`, `evaluation_report_real.csv` y `statistical_comparisons_all.json`) son 100 % consistentes entre sí y con el recálculo directo desde `predictions.csv`. En `host_unseen` Complete-Case ($N_{\text{test}}=691$) bajo `selected_threshold`: **`M0 F1 = 0.865753` (`0.8658`)**, **`M1 F1 = 0.925208` (`0.9252`)**, **`M2 F1 = 0.931507` (`0.9315`)**, **`M3 F1 = 0.928571` (`0.9286`)**, **`M4 F1 = 0.924791` (`0.9248`)**, **`M5 Forzado F1 = 0.924791` (`0.9248`)** y **`M5 Selectivo F1 = 0.953846` (`0.9538` en $N=662$)**. La Sección 3 presenta todas las tablas separadas por experimento, cohorte (`complete_case`, `ite`, `full_corpus`, `authentic_cdp`) y protocolo de umbral (`selected_threshold`, `fixed_0_5`, `low_fpr_threshold`). |
| **R2-3** | **Inconsistencia 3:** Se registran `467` capturas CDP reales en JSONL, pero solo se conservaron `40` archivos PNG en `artifacts/authentic-cdp-screenshots/`. | **PARCIALMENTE RESUELTA (Limitación física documentada)** | En `visual-results-authentic-cdp.jsonl` existen **`467` vectores de características reales** extraídos de capturas Headless Chrome CDP (`76` del `2026-09-30` + `391` del `2026-10-12`). Sin embargo, durante la captura (`scripts/audit_and_capture_authentic_m3.py`, líneas 132–137 y 336: `save_dir=AUTHENTIC_SHOTS_DIR if idx < 40 else None` y `png_path.unlink(missing_ok=True)`), el script solo persistió en disco los primeros **`40` archivos `.png`** (`37` con `status="success"` y `3` descartados tras validación) y eliminó el archivo temporal `.png` de los restantes tras ejecutar `analyze_screenshot(png_path)`. Adicionalmente existen `91` PNG reales en `artifacts/screenshots/` y `16` PNG en `artifacts/visual-samples/`. No es posible recrear hoy los 427 PNG temporales eliminados sin volver a navegar sitios en vivo (lo cual alteraría las marcas de tiempo, latencias y disponibilidad de los sitios de phishing). Cada registro de `visual-results-authentic-cdp.jsonl` incluye ahora el campo `retained_png_path` indicando explícitamente si su PNG físico fue conservado o eliminado tras extraer las características. |
| **R2-4** | **Inconsistencia 4:** El informe anterior identificaba `llama-3.3-70b-versatile`, mientras que las llamadas reales registran `openai/gpt-oss-20b`. | **RESUELTA** | En `src/phishguard_api/llm_agent.py` (líneas 156–161), el agente define una cadena de fallback en Groq (`[GROQ_MODEL, "llama-3.1-8b-instant", "openai/gpt-oss-20b"]`). En el benchmark histórico del `2026-09-30` ($N=100$, $30$ éxitos en `llm_evaluation_results.json`) se utilizó el modelo por defecto `llama-3.1-8b-instant` (sin persistir el campo `usage` de la API). En la evaluación en vivo del `2026-10-12` sobre las 29 abstenciones de M5 (`llm_live_m5_abstained_results.json`, $7$ llamadas completadas con telemetría real de API), el modelo que respondió efectivamente fue **`openai/gpt-oss-20b`**, tal como consta en el campo `"model": "openai/gpt-oss-20b"` de los 7 registros y en `llm_evaluation_summary.json`. La Sección 7 documenta ambos experimentos, sus modelos exactos y sus dos tarifas de costo. |
| **R2-5** | **Inconsistencia 5:** Diferencias en el hardware declarado y en algunas métricas de latencia respecto a los archivos JSON. | **RESUELTA** | El informe previo citó erróneamente un procesador `AMD Ryzen 5 3500U` y valores de latencia de una corrida preliminar. Todos los manifiestos y benchmarks en disco (`latency_benchmark_real.json`, `evaluation_summary_real.json`, `cache_bloom_benchmark.json`, `extension_architecture_and_hybrid_evaluation.json`) registran el hardware real **`13th Gen Intel(R) Core(TM) i5-13600K` (14 núcleos físicos / 20 lógicos, 15.78 GB RAM, Windows 11 `10.0.26200`)**. La Sección 6 reporta exactamente los percentiles y medias contenidos en dichos archivos JSON. |
| **R1-1** | **Objetivo 1:** Entrega de archivos faltantes (`samples.csv`, `*-results-real.jsonl`, modelos `.joblib`, `src/`, dependencias). | **RESUELTA** | Todos los archivos, incluidos `samples.csv` ($176,201$ filas), los 5 archivos `.jsonl` en `artifacts/analysis-results/`, todos los `model.joblib`, `metrics.json`, `predictions.csv`, `src/`, `scripts/`, `pyproject.toml` y `requirements-lock.txt` están empaquetados y verificados en `evidencia_phishpe_corregida_scopus.zip`. |
| **R1-2** | **Objetivo 2:** Eliminar filtración de etiquetas (`y_test`) en la evaluación estadística y de robustez de M5. | **RESUELTA** | Eliminada toda consulta a `y_test` en `predict_all_models_label_blind()` (`scripts/evaluate_robustness_and_stats.py`). Recalculadas todas las comparaciones en cobertura forzada ($N=691$) y en clasificación selectiva pareada ($N=662$), así como las 6 familias de ataques adversariales ($N_{\text{phish}}=191$). |
| **R1-3** | **Objetivo 3:** Auditar M3, separar imágenes sintéticas (`recorded_dom_viewport`) de capturas reales (`live_cdp`) y evaluar M3 auténtico. | **RESUELTA (con limitación de tamaño muestral $N=467$ / $N_{\text{test}}=83$ y 40 PNGs físicos)** | Separados `visual-results-authentic-cdp.jsonl` ($467$ capturas `live_cdp`) y `visual-results-synthetic-dom-proxy.jsonl` ($5,536$ diagramas PIL sintéticos con `"is_synthetic": true`). Entrenado y evaluado `m3-authentic-cdp` sobre las $N=467$ capturas reales (`test = 83`) y evaluada la cascada 100 % real de 3 etapas (`M0 -> M1 -> M2`) sobre $N=691$. |
| **R1-4** | **Objetivo 4:** Separar latencias y costos reales de estimaciones por fórmula. | **PARCIALMENTE RESUELTA (Limitación en timestamp HTTP M2 y cuota gratuita Groq)** | Eliminadas las fórmulas sintéticas de M2 y M3 en `latency_benchmark_real.json`. Medido el parseo DOM real en 97 HTMLs (`P50 = 7.97 ms`), la red M1 en $N=691$ (`P50 = 1,272.65 ms`) y la captura Chrome CDP real en $N=467$ (`P50 = 2,204.78 ms`) y $N=83$ (`P50 = 2,166.36 ms`). Limitaciones documentadas: (1) `content-results-real.jsonl` no guardó el tiempo de socket HTTP GET por separado; (2) el lote histórico de 30 llamadas LLM no guardó `usage` (solo estimación heurística de tokens); (3) la evaluación en vivo de las 29 abstenciones de M5 con `openai/gpt-oss-20b` completó 7 llamadas con telemetría real antes de alcanzar el límite de cuota gratuita de Groq. |
| **R1-5** | **Objetivo 5:** Resolver la inconsistencia en la partición temporal de M0 (`17,725` vs `17,625` filas). | **RESUELTA** | Re-entrenado y evaluado `scripts/train_m0_temporal.py` sobre `splits/temporal.csv` actual (`sha256: 9449ee4e...`, **`17,625` filas de test** en `artifacts/m0-temporal/predictions.csv`) y sobre `splits/temporal_host_unseen.csv` (`sha256: a04b282f...`, **`16,484` filas de test** en `artifacts/m0-temporal-host-unseen/predictions.csv`). El resultado antiguo de 17,725 filas se conserva separado en `artifacts/original_audit_snapshot/m0-temporal/`. |
| **R1-6** | **Objetivo 6:** Verificar si la arquitectura de la extensión coincide con `M0–M5` y evaluar el modelo de la extensión. | **RESUELTA** | Documentadas las 6 diferencias arquitectónicas entre `POST /check` (`HybridM0Model`) y `POST /analyses` (cascada `M0–M5`) y evaluado `HybridM0Model` sobre las mismas $N=691$ muestras de prueba (con y sin escudo Tranco, y midiendo latencia CPU local vs. latencia en vivo con hilos WHOIS/GeoIP) en `extension_architecture_and_hybrid_evaluation.json`. |

---

## 2. Resolución de la Inconsistencia #1: Dataset Canónico (`176,201` muestras), Particiones y Cohortes

### 2.1 Origen y composición exacta de `data/processed/0.1.0/samples.csv`
- **Archivo maestro:** [samples.csv](file:///d:/Proyects/Seguridad_Informacion/data/processed/0.1.0/samples.csv) (`sha256: 947350f084c8d1ee842948ee2cf7607df45bb08e3c3a3f66958e25fc3863b89f`).
- **Metadatos y conteos oficiales:** [statistics.json](file:///d:/Proyects/Seguridad_Informacion/data/processed/0.1.0/statistics.json) y [manifest.json](file:///d:/Proyects/Seguridad_Informacion/data/processed/0.1.0/manifest.json).
- **Registros crudos ingeridos (`raw_records_by_source`):** `176,645` registros (`100,000` dominios benignos de Tranco Top-1M + `76,645` URLs de phishing verificadas de PhishTank, con `source_timestamp` entre `2011-02-19T00:05:43Z` y `2026-09-19T17:01:55Z`).
- **Exclusiones durante la deduplicación y sanitización (`444` registros excluidos):**
  - `duplicate_same_label`: `428`
  - `conflicting_label`: `13`
  - `invalid_url:empty_or_too_long`: `2`
  - `invalid_url:control_character`: `1`
- **Total del corpus canónico (`samples.csv`):** **`176,201` muestras únicas**:
  - **Legítimas (`label == "legitimate"`, fuente `tranco`):** **`99,994`** (`56.75 %`)
  - **Phishing (`label == "phishing"`, fuente `phishtank`):** **`76,207`** (`43.25 %`)

### 2.2 Tabla Maestra de Particiones y Cohortes Verificadas en Disco

Todas las particiones están definidas en `data/processed/0.1.0/splits/*.csv`. El subconjunto multimodal de **`10,000` URLs** (`5,675` legítimas y `4,325` phishing) fue muestreado de forma estratificada el `2026-09-19` (`scripts/batch_analyze.py`) y hereda exactamente la asignación `sample_id -> partition` del corpus de `176,201` URLs:

| Nivel / Cohorte | Archivo de Partición (`splits/*.csv`) | Hash SHA-256 (primeros 16 hex) | Total Muestras | `train` (Legit / Phish = Total) | `validation` (Legit / Phish = Total) | `test` (Legit / Phish = Total) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **1. Corpus Completo (`176,201`)** | `conventional.csv` | `12472e740d17678e` | **176,201** | `69,996 / 53,345 = 123,341` | `14,999 / 11,431 = 26,430` | `14,999 / 11,431 = 26,430` |
| **1. Corpus Completo (`176,201`)** | `host_unseen.csv` | `8adc72928bf6d694` | **176,201** | `69,996 / 53,345 = 123,341` | `14,999 / 11,431 = 26,430` | `14,999 / 11,431 = 26,430` |
| **1. Corpus Completo (`176,201`)** | `temporal.csv` | `9449ee4e0c31cdba` | **176,201** | `80,164 / 60,965 = 141,129` | `9,826 / 7,621 = 17,447` | `10,004 / 7,621 = 17,625` |
| **1. Corpus Completo Host-Disjoint (`173,633`)** | `temporal_host_unseen.csv` | `a04b282fee73b9ab` | **173,633** | `80,164 / 60,965 = 141,129` | `9,776 / 6,244 = 16,020` | `9,959 / 6,525 = 16,484` |
| **2. Cohorte Multimodal ITE (`10,000`)** | `host_unseen.csv` | `8adc72928bf6d694` | **10,000** | `3,973 / 3,028 = 7,001` | `851 / 648 = 1,499` | `851 / 649 = 1,500` |
| **2. Cohorte Multimodal ITE (`10,000`)** | `conventional.csv` | `12472e740d17678e` | **10,000** | `3,957 / 3,004 = 6,961` | `862 / 642 = 1,504` | `856 / 679 = 1,535` |
| **2. Cohorte Multimodal ITE (`10,000`)** | `temporal.csv` | `9449ee4e0c31cdba` | **10,000** | `4,571 / 3,456 = 8,027` | `567 / 442 = 1,009` | `537 / 427 = 964` |
| **2. Cohorte Multimodal ITE (`9,858`)** | `temporal_host_unseen.csv` | `a04b282fee73b9ab` | **9,858** | `4,571 / 3,456 = 8,027` | `565 / 364 = 929` | `535 / 367 = 902` |
| **3. Cohorte Complete-Case CC (`5,612`)** | `host_unseen.csv` | `8adc72928bf6d694` | **5,612** | `2,388 / 1,831 = 4,219` | `517 / 185 = 702` | **`500 / 191 = 691`** |
| **3. Cohorte Complete-Case CC (`5,612`)** | `conventional.csv` | `12472e740d17678e` | **5,612** | `2,341 / 1,509 = 3,850` | `536 / 329 = 865` | `528 / 369 = 897` |
| **3. Cohorte Complete-Case CC (`5,612`)** | `temporal.csv` | `9449ee4e0c31cdba` | **5,612** | `2,727 / 2,137 = 4,864` | `357 / 23 = 380` | `321 / 47 = 368` |
| **3. Cohorte Complete-Case CC (`5,583`)** | `temporal_host_unseen.csv` | `a04b282fee73b9ab` | **5,583** | `2,727 / 2,137 = 4,864` | `356 / 15 = 371` | `319 / 29 = 348` |
| **4. Cohorte Visual Chrome CDP Real (`467`)** | `host_unseen.csv` | `8adc72928bf6d694` | **467** | `150 / 163 = 313` | `34 / 37 = 71` | **`55 / 28 = 83`** |

---

## 3. Resolución de la Inconsistencia #2: Métricas Exactas de Clasificación (`M0–M5`) por Experimento, Cohorte y Protocolo de Umbral

### 3.1 Conteo Exacto de Características (`feature-registry.json` y `evaluation_summary_real.json`)
- **`M0` (`11` variables — perfil `authority_only`):** `host_length`, `registered_domain_length`, `host_label_count`, `subdomain_count`, `host_digit_count`, `host_digit_ratio`, `host_hyphen_count`, `host_entropy`, `has_ip_host`, `has_punycode`, `tld_length`.
- **`M1` (`36` variables = `11` M0 + `25` Infraestructura DNS/RDAP/TLS):** Añade disponibilidad/estado de red, conteos IPv4/IPv6, redirecciones, cambio de dominio, estado TLS, validez/emisor/SAN del certificado y dispersión de subred `/24` (*Fast-Flux*).
- **`M2` (`62` variables = `36` M1 + `26` Contenido HTML/DOM):** Añade tamaño y estado HTTP, conteos de etiquetas/formularios/inputs sensibles (`password`, `email`, `payment`), enlaces/recursos externos, términos de login/pago y 5 indicadores de exfiltración de formularios.
- **`M3`, `M4_fixed`, `M4`, `M5` (`75` variables = `62` M2 + `13` Visuales):** Añade dimensiones, luminancia media/desviación, densidad de bordes, ratio de píxeles oscuros/saturados, distancia perceptual `pHash` mínima y similitud de histograma `HSV` frente a plantillas de marca.

---

### 3.2 Experimento Principal 1: Cohorte Multimodal `host_unseen` Complete-Case ($N_{\text{test}} = 691$: 500 legítimas, 191 phishing)

**Script generador:** [train_and_evaluate_all_real.py](file:///d:/Proyects/Seguridad_Informacion/scripts/train_and_evaluate_all_real.py)  
**Archivos de resumen:** [evaluation_summary_real.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/evaluation_summary_real.json) y [evaluation_report_real.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/evaluation_report_real.csv).

Cada archivo `artifacts/m*-real/metrics.json` almacena tres puntos de operación sobre las mismas $N = 691$ muestras de prueba:
1. **`selected_threshold` ($\tau^*$):** Umbral óptimo en F1 seleccionado sobre la sub-partición `validation_selection` ($N=344$). **Es el umbral oficial utilizado para generar la columna `predicted_label` en `predictions.csv`, la Tabla 1 (`evaluation_report_real.csv`) y las comparaciones estadísticas (`statistical_comparisons_all.json`).**
2. **`fixed_0_5` ($\tau = 0.50$):** Corte estándar fijo en probabilidad `0.50`.
3. **`low_fpr_threshold` ($\tau_{\text{low-FPR}}$):** Umbral seleccionado en `validation_selection` para mantener $\text{FPR} \le 1\%$.

#### Tabla 3.2A — Punto de Operación Primario (`selected_threshold`, verificado contra `predictions.csv` y `evaluation_report_real.csv`)

| Modelo | Carpeta de Artefactos (`metrics.json` y `predictions.csv`) | Candidato Seleccionado | Feat. | Protocolo / Cobertura | $N_{\text{eval}}$ | Umbral $\tau^*$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR | ROC-AUC | PR-AUC | Brier | ECE |
| :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M0** | `artifacts/m0-real/` | `histgb-63-sigmoid` | 11 | Cobertura Total (100 %) | 691 | `0.382667` | 484 | 16 | 33 | 158 | `0.929088` | `0.908046` | `0.827225` | **`0.865753`** (`0.8658`) | `0.0320` | `0.909749` | `0.899075` | `0.063633` | `0.081722` |
| **M1** | `artifacts/m1-real/` | `histgb-31-sigmoid` | 36 | Cobertura Total (100 %) | 691 | `0.525014` | 497 | 3 | 24 | 167 | `0.960926` | `0.982353` | `0.874346` | **`0.925208`** (`0.9252`) | `0.0060` | `0.975937` | `0.963361` | `0.036119` | `0.024551` |
| **M2** | `artifacts/m2-real/` | `histgb-31-sigmoid` | 62 | Cobertura Total (100 %) | 691 | `0.394962` | 496 | 4 | 21 | 170 | `0.963821` | `0.977011` | `0.890052` | **`0.931507`** (`0.9315`) | `0.0080` | `0.986366` | `0.980484` | `0.028996` | `0.020335` |
| **M3** *(CC)* | `artifacts/m3-real/` | `histgb-63-sigmoid` | 75 | Cobertura Total (100 %) | 691 | `0.434336` | 496 | 4 | 22 | 169 | `0.962373` | `0.976879` | `0.884817` | **`0.928571`** (`0.9286`) | `0.0080` | `0.985005` | `0.978788` | `0.028541` | `0.016106` |
| **M4_fixed** | `artifacts/m4-fixed-real/` | Cascada fija sin calibrar | 75 | Cobertura Total (100 %) | 691 | `0.434336` | 499 | 1 | 33 | 158 | `0.950796` | `0.993711` | `0.827225` | **`0.902857`** (`0.9029`) | `0.0020` | `0.921702` | `0.909337` | `0.049425` | `0.049257` |
| **M4** | `artifacts/m4-real/` | Cascada calibrada ($H_{\text{esc}}=0.15$) | 75 | Cobertura Total (100 %) | 691 | Por etapa ($\tau_k$) | 498 | 2 | 25 | 166 | `0.960926` | `0.988095` | `0.869110` | **`0.924791`** (`0.9248`) | `0.0040` | `0.967351` | `0.961723` | `0.033182` | `0.026008` |
| **M5 (Forzado)** | `artifacts/m5-real/` (`selected_threshold`) | Cascada calibrada sin abstenerse | 75 | Cobertura Total Forzada (100 %) | 691 | Por etapa ($\tau_k$) | 498 | 2 | 25 | 166 | `0.960926` | `0.988095` | `0.869110` | **`0.924791`** (`0.9248`) | `0.0040` | `0.967351` | `0.961723` | `0.033182` | `0.026008` |
| **M5 (Selectivo)** | `artifacts/m5-real/` (`selective_metrics`) | Cascada + Abstención ($H_{\text{abs}}=0.50$) | 75 | **Selectivo (`95.8032 %` cob., 29 abst.: 21 phish, 8 legit)** | **662** | Por etapa ($\tau_k$) | **492** | **0** | **15** | **155** | **`0.977341`** | **`1.000000`** | **`0.911765`** | **`0.953846`** (`0.9538`) | **`0.0000`** | `0.967351` | `0.961723` | `0.033182` | `0.017304` |

#### Tabla 3.2B — Puntos de Operación Alternativos en `metrics.json` (`fixed_0_5` y `low_fpr_threshold`) sobre $N_{\text{test}} = 691$

Para evitar cualquier confusión al inspeccionar las claves internas `fixed_0_5` y `low_fpr_threshold` dentro de `artifacts/m0-real/metrics.json` a `m3-real/metrics.json`, se listan aquí sus valores exactos:

| Modelo | Sub-clave en `metrics.json` | Umbral $\tau$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M0** (`m0-real/metrics.json`) | `fixed_0_5` | `0.500000` | 493 | 7 | 35 | 156 | `0.939219` | `0.957055` | `0.816754` | **`0.881356`** | `0.0140` |
| **M0** (`m0-real/metrics.json`) | `low_fpr_threshold` | `0.572067` | 494 | 6 | 36 | 155 | `0.939219` | `0.962733` | `0.811518` | **`0.880682`** | `0.0120` |
| **M1** (`m1-real/metrics.json`) | `fixed_0_5` | `0.500000` | 497 | 3 | 24 | 167 | `0.960926` | `0.982353` | `0.874346` | **`0.925208`** | `0.0060` |
| **M1** (`m1-real/metrics.json`) | `low_fpr_threshold` | `0.357459` | 494 | 6 | 22 | 169 | `0.959479` | `0.965714` | `0.884817` | **`0.923497`** | `0.0120` |
| **M2** (`m2-real/metrics.json`) | `fixed_0_5` | `0.500000` | 497 | 3 | 24 | 167 | `0.960926` | `0.982353` | `0.874346` | **`0.925208`** | `0.0060` |
| **M2** (`m2-real/metrics.json`) | `low_fpr_threshold` | `0.449967` | 497 | 3 | 23 | 168 | `0.962373` | `0.982456` | `0.879581` | **`0.928177`** | `0.0060` |
| **M3** (`m3-real/metrics.json`) | `fixed_0_5` | `0.500000` | 497 | 3 | 25 | 166 | `0.959479` | `0.982249` | `0.869110` | **`0.922222`** | `0.0060` |
| **M3** (`m3-real/metrics.json`) | `low_fpr_threshold` | `0.434336` | 496 | 4 | 22 | 169 | `0.962373` | `0.976879` | `0.884817` | **`0.928571`** | `0.0080` |

---

### 3.3 Experimento 2: Cohorte Multimodal `host_unseen` Intention-to-Evaluate (`ITE`, $N_{\text{test}} = 1,500$: 851 legítimas, 649 phishing)

**Script generador:** [train_and_evaluate_all_real.py](file:///d:/Proyects/Seguridad_Informacion/scripts/train_and_evaluate_all_real.py)  
**Archivos de evidencia:** `artifacts/m0-ite-real/` a `artifacts/m3-ite-real/`, [evaluation_summary_real.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/evaluation_summary_real.json) (`multimodal_cohort.host_unseen.ite`) y [evaluation_report_real.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/evaluation_report_real.csv).

| Modelo (`ITE`) | Carpeta / Archivo de Evidencia | Protocolo | $N_{\text{eval}}$ | Umbral $\tau^*$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1 (`selected_threshold`)** | **F1 (`fixed_0_5`)** | FPR | ROC-AUC | PR-AUC | Brier |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M0 (`ITE`)** | `artifacts/m0-ite-real/` | Cobertura Total (100 %) | 1,500 | `0.412708` | 820 | 31 | 129 | 520 | `0.893333` | `0.943739` | `0.801233` | **`0.866667`** | `0.863406` | `0.0364` | `0.905057` | `0.926524` | `0.087837` |
| **M1 (`ITE`)** | `artifacts/m1-ite-real/` | Cobertura Total (100 %) | 1,500 | `0.564585` | 827 | 24 | 113 | 536 | `0.908667` | `0.957143` | `0.825886` | **`0.886683`** | `0.886345` | `0.0282` | `0.962700` | `0.962871` | `0.067703` |
| **M2 (`ITE`)** | `artifacts/m2-ite-real/` | Cobertura Total (100 %) | 1,500 | `0.596635` | 831 | 20 | 110 | 539 | `0.913333` | `0.964222` | `0.830508` | **`0.892384`** | `0.894522` | `0.0235` | `0.969715` | `0.968158` | `0.063317` |
| **M3 (`ITE`)** | `artifacts/m3-ite-real/` | Cobertura Total (100 %) | 1,500 | `0.455440` | 817 | 34 | 90 | 559 | `0.917333` | `0.942664` | `0.861325` | **`0.900161`** | `0.893409` | `0.0400` | `0.969685` | `0.968213` | `0.063360` |
| **M4_fixed (`ITE`)** | `evaluation_summary_real.json` | Cobertura Total (100 %) | 1,500 | `0.455440` | 828 | 23 | 108 | 541 | `0.912667` | `0.959220` | `0.833590` | **`0.892003`** | — | `0.0270` | `0.926475` | `0.939792` | `0.074627` |
| **M4 (`ITE`)** | `evaluation_summary_real.json` | Cobertura Total ($H_{\text{esc}}=0.45$) | 1,500 | Por etapa | 817 | 34 | 93 | 556 | `0.915333` | `0.942373` | `0.856703` | **`0.897498`** | — | `0.0400` | `0.960280` | `0.961654` | `0.067814` |
| **M5 (`ITE`, Selectivo)** | `evaluation_summary_real.json` | Selectivo (`94.4667 %` cob., 83 abst.) | 1,417 | Por etapa | 783 | 17 | 79 | 538 | `0.932251` | `0.969369` | `0.871961` | **`0.918089`** | — | `0.0213` | `0.960280` | `0.961654` | `0.067814` |

---

### 3.4 Experimento 3: Evaluaciones de `M0` sobre el Corpus Completo (`176,201` y `173,633` muestras)

**Scripts generadores:** `src/phishguard_ml/cli.py` y [train_m0_temporal.py](file:///d:/Proyects/Seguridad_Informacion/scripts/train_m0_temporal.py)  
**Archivos de evidencia:** `artifacts/url-baseline-0.2.0/`, `artifacts/m0-temporal/`, `artifacts/m0-temporal-host-unseen/` y [evaluation_summary_real.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/evaluation_summary_real.json) (`full_corpus_m0`).

| Experimento / Artefacto | Partición (`splits/*.csv`) | Filas Totales `predictions.csv` | Filas `test` | Umbral Seleccionado $\tau^*$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1 (`selected_threshold`)** | **F1 (`threshold_0_5`)** | FPR | ROC-AUC | PR-AUC | Brier |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`artifacts/url-baseline-0.2.0/`** | `host_unseen.csv` | 176,201 | **26,430** | `0.433937` | 14,423 | 576 | 2,225 | 9,206 | `0.894022` | `0.941116` | `0.805354` | **`0.867958`** | `0.866909` | `0.0384` | `0.929576` | `0.940684` | `0.082448` |
| **`artifacts/m0-temporal/`** *(Alineado con `temporal.csv` actual)* | `temporal.csv` | 176,201 | **17,625** | `0.274225` | 9,550 | 454 | 1,884 | 5,737 | `0.867348` | `0.926668` | `0.752788` | **`0.830727`** | `0.794728` | `0.0454` | `0.914691` | `0.924110` | `0.107695` |
| **`artifacts/m0-temporal-host-unseen/`** *(Nuevo, estricto)* | `temporal_host_unseen.csv` | 173,633 | **16,484** | `0.256980` | 9,507 | 452 | 1,773 | 4,752 | `0.865021` | `0.913144` | `0.728276` | **`0.810299`** | `0.769902` | `0.0454` | `0.904573` | `0.906599` | `0.109831` |

---

### 3.5 Experimento 4: Evaluación Visual 100 % Auténtica con Chrome CDP ($N_{\text{total}} = 467$, $N_{\text{test}} = 83$) y Cascada de 3 Etapas `M0 -> M2` ($N_{\text{test}} = 691$)

**Script generador:** [audit_and_capture_authentic_m3.py](file:///d:/Proyects/Seguridad_Informacion/scripts/audit_and_capture_authentic_m3.py) y [sync_and_enrich_audit_artifacts.py](file:///d:/Proyects/Seguridad_Informacion/scripts/sync_and_enrich_audit_artifacts.py)  
**Archivos de evidencia:** [m3_visual_audit_and_authentic_evaluation.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json), [artifacts/corrected_audit/m3-authentic-cdp/metrics.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/m3-authentic-cdp/metrics.json) y [artifacts/corrected_audit/m3-authentic-cdp/predictions.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/m3-authentic-cdp/predictions.csv).

#### Tabla 3.5A — Modelos `M0–M3` sobre la Cohorte 100 % Chrome CDP Real (`host_unseen`, `train = 313`, `validation = 71`, `test = 83`: 55 legítimas, 28 phishing)

| Modelo (Cohorte 100 % Chrome CDP Real) | Candidato Seleccionado | Feat. | $N_{\text{test}}$ | Umbral $\tau^*$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR | ROC-AUC | PR-AUC | Brier | ECE |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M0 (`live_cdp` cohort)** | `histgb-31-sigmoid` | 11 | 83 | `0.435440` | 43 | 12 | 3 | 25 | `0.819277` | `0.675676` | `0.892857` | **`0.769231`** | `0.2182` | `0.955844` | `0.945569` | `0.095807` | `0.164253` |
| **M1 (`live_cdp` cohort)** | `logreg-l2-c01-sigmoid` | 36 | 83 | `0.530709` | 49 | 6 | 3 | 25 | `0.891566` | `0.806452` | `0.892857` | **`0.847458`** | `0.1091` | `0.914935` | `0.844416` | `0.103432` | `0.136446` |
| **M2 (`live_cdp` cohort)** | `histgb-31-isotonic` | 62 | 83 | `0.786429` | 55 | 0 | 4 | 24 | `0.951807` | `1.000000` | `0.857143` | **`0.923077`** | `0.0000` | `0.967857` | `0.948840` | `0.063069` | `0.097081` |
| **M3 (`m3-authentic-cdp`)** | `histgb-31-isotonic` | 75 | 83 | `0.500000` | 51 | 4 | 2 | 26 | `0.927711` | `0.866667` | **`0.928571`** | **`0.896552`** | `0.0727` | **`0.978896`** | **`0.962271`** | **`0.051734`** | **`0.090169`** |

> **Interpretación científica honesta (conservando el resultado desfavorable puntual):** En la cohorte 100 % real de capturas Chrome CDP ($N_{\text{test}}=83$), añadir las 13 variables visuales reales de M3 mejora el **Recall** (`0.857143 -> 0.928571`, detectando 26/28 ataques de phishing frente a 24/28 de M2), el **ROC-AUC** (`0.967857 -> 0.978896`), el **PR-AUC** (`0.948840 -> 0.962271`), el **Brier Score** (`0.063069 -> 0.051734`) y el **ECE** (`0.097081 -> 0.090169`). En validación ($N=71$), M3 también supera a M2 en F1 (`0.944444` vs. `0.942857`). Sin embargo, en el conjunto de prueba ($N=83$), 4 muestras legítimas superan el umbral $\tau=0.50$, reduciendo la precisión puntual a `0.866667` y situando el F1 puntual de prueba en `0.896552` frente a `0.923077` de M2.

#### Tabla 3.5B — Cascada de 3 Etapas Estrictamente Real (`M0 -> M1 -> M2`, 0 % características visuales sintéticas) sobre $N_{\text{test}} = 691$

Respaldado en `evaluation_summary_real.json` (clave `m0_to_m2_strictly_real_cascade_n691`) y `m3_visual_audit_and_authentic_evaluation.json`:

| Configuración (Cascada 3 etapas M0->M1->M2) | Protocolo / Cobertura | $N_{\text{eval}}$ | Abstenciones | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR | ECE | Modalidades Promedio |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`M4_M2` (`m4_m2_forced_full_coverage`)** | Cobertura Total Forzada (`100.00 %`) | 691 | 0 | 497 | 3 | 25 | 166 | `0.959479` | `0.982249` | `0.869110` | **`0.922222`** | `0.0060` | — | `1.8509` (`M0: 270, M1: 254, M2: 167`) |
| **`M5_M2` (`m5_m2_selective_with_abstention`)** | Selectiva (`96.3821 %` cobertura) | 666 | **25** (`15` phish, `10` legit) | 490 | 0 | 17 | 159 | `0.974474` | **`1.000000`** | **`0.903409`** | **`0.949254`** | **`0.0000`** | `0.019230` | `1.8509` (`M0: 270, M1: 254, M2: 167`) |

---

## 4. Comparaciones Estadísticas Pareadas Libres de Filtración de Etiquetas (`statistical_comparisons_all.json`)

**Script generador:** [evaluate_robustness_and_stats.py](file:///d:/Proyects/Seguridad_Informacion/scripts/evaluate_robustness_and_stats.py)  
**Archivos de evidencia:** [statistical_comparisons_all.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/statistical_comparisons_all.json) y [statistical_comparisons_all.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/statistical_comparisons_all.csv).

| Comparación (`statistical_comparisons_all.json`) | Protocolo de Evaluación | $N$ Pareado | F1 Modelo A | F1 Modelo B | $\Delta F_1$ ($B - A$) | IC 95 % Bootstrap ($B=1,000$) | Prec A $\to$ B | Rec A $\to$ B | Acc A $\to$ B | McNemar ($a_{\text{only}}$ vs $b_{\text{only}}$) | McNemar $p$ Exacto | $p_{\text{Holm}}$ (vs M0) | Sig. ($\alpha=0.05$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`M0_vs_M1`** | Cobertura Forzada ($N=691$) | 691 | `0.865753` | `0.925208` | **`+0.059454`** | `[+0.032443, +0.087346]` | `0.9080 -> 0.9824` | `0.8272 -> 0.8743` | `0.9291 -> 0.9609` | `2` vs `24` | `1.049e-05` | `4.196e-05` | **Sí** |
| **`M0_vs_M2`** | Cobertura Forzada ($N=691$) | 691 | `0.865753` | `0.931507` | **`+0.065753`** | `[+0.035922, +0.096547]` | `0.9080 -> 0.9770` | `0.8272 -> 0.8901` | `0.9291 -> 0.9638` | `5` vs `29` | `3.856e-05` | `7.712e-05` | **Sí** |
| **`M0_vs_M3`** | Cobertura Forzada ($N=691$) | 691 | `0.865753` | `0.928571` | **`+0.062818`** | `[+0.033608, +0.096392]` | `0.9080 -> 0.9769` | `0.8272 -> 0.8848` | `0.9291 -> 0.9624` | `6` vs `29` | `0.00011684` | `0.00011684` | **Sí** |
| **`M0_vs_M4`** | Cobertura Forzada ($N=691$) | 691 | `0.865753` | `0.924791` | **`+0.059038`** | `[+0.032406, +0.089246]` | `0.9080 -> 0.9881` | `0.8272 -> 0.8691` | `0.9291 -> 0.9609` | `3` vs `25` | `2.744e-05` | `8.232e-05` | **Sí** |
| **`M0_vs_M5_forced_full_coverage`** | Cobertura Forzada ($N=691$) | 691 | `0.865753` | `0.924791` | **`+0.059038`** | `[+0.032406, +0.089246]` | `0.9080 -> 0.9881` | `0.8272 -> 0.8691` | `0.9291 -> 0.9609` | `3` vs `25` | `2.744e-05` | — | **Sí** |
| **`M1_vs_M2`** | Cobertura Forzada ($N=691$) | 691 | `0.925208` | `0.931507` | `+0.006299` | `[-0.013673, +0.027593]` | `0.9824 -> 0.9770` | `0.8743 -> 0.8901` | `0.9609 -> 0.9638` | `6` vs `8` | `0.79052734` | — | No |
| **`M2_vs_M3`** | Cobertura Forzada ($N=691$) | 691 | `0.931507` | `0.928571` | `-0.002935` | `[-0.020119, +0.014623]` | `0.9770 -> 0.9769` | `0.8901 -> 0.8848` | `0.9638 -> 0.9624` | `5` vs `4` | `1.0` | — | No |
| **`M3_vs_M4`** | Cobertura Forzada ($N=691$) | 691 | `0.928571` | `0.924791` | `-0.003780` | `[-0.019903, +0.011471]` | `0.9769 -> 0.9881` | `0.8848 -> 0.8691` | `0.9624 -> 0.9609` | `4` vs `3` | `1.0` | — | No |
| **`M0_vs_M5` (`M0_vs_M5_on_decided_subset_N662`)** | **Selectivo Pareado ($N=662$ decididas; 29 abst.: 21 phish, 8 legit)** | **662** | **`0.896142`** | **`0.953846`** | **`+0.057704`** | **`[+0.035305, +0.084160]`** | **`0.9042 -> 1.0000`** | **`0.8882 -> 0.9118`** | **`0.9471 -> 0.9773`** | **`0` vs `20`** | **`1.91e-06`** | **`9.55e-06`** | **Sí** |
| **`M3_vs_M5_on_decided_subset_N662`** | Selectivo Pareado ($N=662$ decididas) | 662 | `0.957576` | `0.953846` | `-0.003730` | `[-0.019061, +0.011108]` | `0.9875 -> 1.0000` | `0.9294 -> 0.9118` | `0.9789 -> 0.9773` | `4` vs `3` | `1.0` | — | No |

---

## 5. Evaluación de Robustez Adversarial Libre de Filtración de Etiquetas ($N_{\text{phish}} = 191$, $N_{\text{legit}} = 500$)

**Script generador:** [evaluate_robustness_and_stats.py](file:///d:/Proyects/Seguridad_Informacion/scripts/evaluate_robustness_and_stats.py)  
**Archivos de evidencia:** [robustness_evaluation_real.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/robustness_evaluation_real.json) y [robustness_evaluation_real.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/robustness_evaluation_real.csv).

En las 6 familias de perturbación en espacio de características (`phishguard_robustness.perturbations.perturb_feature_matrix`), las predicciones son 100 % ciegas a `y_test`. Para `M5`, se reportan por separado:
- **Forced Binary Recall (`perturbed_forced_recall`):** Recall binario si se desactiva la abstención ($N=191$, idéntico a `M4`).
- **Direct Unflagged Recall (`perturbed_direct_recall`):** Muestras de phishing detectadas directamente sin abstenerse ($\text{TP}_{\text{direct}} / 191$).
- **Selective Recall on Decided (`perturbed_selective_recall_on_decided`):** Recall sobre las muestras de phishing no abstenidas ($\text{TP}_{\text{direct}} / (191 - N_{\text{abstained, phish}})$).
- **Protective Interception Rate (`protective_interception_rate`):** Proporción de las 191 muestras de phishing que son bloqueadas directamente o retenidas en la cola de abstención ($(\text{TP}_{\text{direct}} + N_{\text{abstained, phish}}) / 191$).
- **Forced Binary ASR (`forced_binary_asr`):** Fracción de los ataques detectados en limpio (`TP_clean = 166`) que pasan a $\hat{y} = 0$ en decisión forzada.
- **Silent Bypass ASR (`silent_bypass_asr`):** Fracción de los ataques interceptados en limpio (`176`) que logran evadir silenciosamente a `M5` como benignos decididos ($\hat{y} = 0$ y $\text{abstain} = \text{False}$).

| Familia de Ataque (`atk_key`) | M0 Recall (ASR) | M1 Recall (ASR) | M2 Recall (ASR) | M3 Recall (ASR) | M4 / M5 Forced Recall (Forced ASR) | M5 Direct Recall ($/191$) | M5 Selective Recall (Decided) | M5 Protective Interception | M5 Abstención Phishing ($/191$) | M5 Abstención Legítimas ($/500$) | **M5 Silent Bypass ASR** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Limpio (Sin perturbación)** | `0.827225` (—) | `0.874346` (—) | `0.890052` (—) | `0.884817` (—) | `0.869110` (—) | `0.811518` | `0.911765` | `0.921466` | `21` (`0.109948`) | `8` (`0.0160`) | — |
| **1. `url_evasion`** | `0.073298` (`0.911392`) | `0.151832` (`0.826347`) | `0.513089` (`0.423529`) | `0.549738` (`0.378698`) | **`0.345550` (`0.614458`)** | `0.073298` | `0.135922` | `0.534031` | **`88` (`0.460733`)** | `8` (`0.0160`) | **`0.437500`** |
| **2. `homograph_punycode`** | `0.073298` (`0.911392`) | `0.151832` (`0.826347`) | `0.513089` (`0.423529`) | `0.549738` (`0.378698`) | **`0.345550` (`0.614458`)** | `0.073298` | `0.135922` | `0.534031` | **`88` (`0.460733`)** | `8` (`0.0160`) | **`0.437500`** |
| **3. `infra_evasion`** | `0.827225` (`0.000000`) | `0.816754` (`0.065868`) | `0.874346` (`0.017647`) | `0.884817` (`0.005917`) | **`0.869110` (`0.006024`)** | `0.795812` | `0.888889` | `0.900524` | `20` (`0.104712`) | `8` (`0.0160`) | **`0.022727`** |
| **4. `dom_obfuscation`** | `0.827225` (`0.000000`) | `0.874346` (`0.000000`) | `0.858639` (`0.035294`) | `0.863874` (`0.023669`) | **`0.853403` (`0.018072`)** | `0.738220` | `0.870370` | `0.890052` | `29` (`0.151832`) | `8` (`0.0160`) | **`0.034091`** |
| **5. `visual_noise`** | `0.827225` (`0.000000`) | `0.874346` (`0.000000`) | `0.890052` (`0.000000`) | `0.890052` (`0.005917`) | **`0.874346` (`0.000000`)** | `0.816754` | `0.917647` | `0.926702` | `21` (`0.109948`) | `8` (`0.0160`) | **`0.000000`** |
| **6. `combined_multimodal`** | `0.073298` (`0.911392`) | `0.083770` (`0.904192`) | `0.120419` (`0.864706`) | `0.078534` (`0.911243`) | **`0.078534` (`0.909639`)** | `0.073298` | `0.100719` | `0.345550` | **`52` (`0.272251`)** | `8` (`0.0160`) | **`0.630682`** |

---

## 6. Resolución de la Inconsistencia #3: Auditoría de las 467 Capturas Chrome CDP y los 40 Archivos PNG Conservados

**Archivos de evidencia:**
- [visual-results-authentic-cdp.jsonl](file:///d:/Proyects/Seguridad_Informacion/artifacts/analysis-results/visual-results-authentic-cdp.jsonl) (`10,000` registros totales: **`467`** con `capture_mode: "live_cdp"` y `status: "success"`, `149` con `capture_mode: "live_cdp_failed"`, y `9,384` con `status: "not_captured"`).
- [visual-results-synthetic-dom-proxy.jsonl](file:///d:/Proyects/Seguridad_Informacion/artifacts/analysis-results/visual-results-synthetic-dom-proxy.jsonl) (`5,536` registros sintéticos etiquetados con `"capture_mode": "synthetic_dom_viewport_pil"` e `"is_synthetic": true`).
- [m3_visual_audit_and_authentic_evaluation.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json) (sección `png_retention_audit`).

### 6.1 Explicación exacta de la diferencia entre `467` registros CDP y `40` archivos PNG en `artifacts/authentic-cdp-screenshots/`
1. **Origen de los 467 vectores de características `live_cdp`:**
   - **`76` registros** provienen de la corrida de captura CDP en vivo del `2026-09-30` (`scripts/capture_visual_real.py`), donde Headless Chrome capturó el PNG en un directorio temporal, extrajo las 13 características visuales (`analyze_screenshot`) y eliminó el archivo PNG temporal tras guardar el vector numérico en JSONL.
   - **`391` registros** provienen de la corrida de expansión CDP en vivo del `2026-10-12` ([audit_and_capture_authentic_m3.py](file:///d:/Proyects/Seguridad_Informacion/scripts/audit_and_capture_authentic_m3.py), líneas 130–138 y 336).
2. **Por qué solo se conservaron `40` archivos `.png` en `artifacts/authentic-cdp-screenshots/`:**
   - En [audit_and_capture_authentic_m3.py](file:///d:/Proyects/Seguridad_Informacion/scripts/audit_and_capture_authentic_m3.py#L336), la llamada a `capture_live_cdp_one` se configuró con:
     ```python
     save_dir=AUTHENTIC_SHOTS_DIR if idx < 40 else None
     ```
     y en la línea 137:
     ```python
     vis_res = analyze_screenshot(png_path)
     png_path.unlink(missing_ok=True)
     ```
   - Es decir, para **las 391 capturas nuevas**, Chrome Headless generó el archivo PNG real en `tmp_shot_dir`, `analyze_screenshot(png_path)` calculó las 13 variables visuales reales (`visual_width`, `visual_height`, `visual_mean_luminance`, `visual_phash_distance_min`, `visual_hsv_similarity_max`, etc.) y el tamaño en bytes (`bytes_received`), pero el script solo copió a `artifacts/authentic-cdp-screenshots/` los primeros **40 archivos PNG** (`37` con `status == "success"` y `3` que resultaron en error/imagen vacía) como muestra física de auditoría, eliminando (`unlink`) los demás archivos temporales `.png` para no añadir cientos de megabytes al repositorio.
3. **Inventario completo de archivos PNG físicos reales incluidos en el paquete ZIP:**
   - `artifacts/authentic-cdp-screenshots/`: **`40` archivos `.png`** (`37` vinculados a registros `live_cdp` exitosos mediante el campo `"retained_png_path"` en `visual-results-authentic-cdp.jsonl`, y `3` vinculados a intentos `live_cdp` descartados).
   - `artifacts/screenshots/`: **`91` archivos `.png`** reales capturados por el worker del sandbox sobre `32` URLs únicas (junto con sus **`97` archivos `.html`** en `artifacts/previews/`).
   - `artifacts/visual-samples/`: **`16` archivos `.png`** de muestras visuales y plantillas.
4. **Declaración de limitación para el artículo:**
   - Se dispone de los **`467` vectores de características visuales 100 % reales** extraídos de capturas Headless Chrome CDP (`train=313, validation=71, test=83`) y de **`147` archivos PNG reales en disco** (`40 + 91 + 16`), pero los restantes `430` buffers PNG crudos fueron eliminados en tiempo de extracción tras computar sus descriptores `analyze_screenshot()`. Esta limitación queda explícitamente declarada como **`PARCIALMENTE RESUELTA`** en la matriz de validación.

---

## 7. Resolución de la Inconsistencia #4: Modelos LLM Utilizados (`llama-3.1-8b-instant` vs. `openai/gpt-oss-20b`), Telemetría y Costos

**Script generador:** [evaluate_llm.py](file:///d:/Proyects/Seguridad_Informacion/scripts/evaluate_llm.py) y [llm_agent.py](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/llm_agent.py)  
**Archivos de evidencia:**
- [llm_evaluation_summary.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/llm_evaluation_summary.json)
- [llm_evaluation_results.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/llm_evaluation_results.json) (100 registros del benchmark histórico del `2026-09-30`)
- [llm_live_m5_abstained_results.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/llm_live_m5_abstained_results.json) (29 registros de las muestras abstenidas por M5 evaluadas en vivo el `2026-10-12`)

### 7.1 Aclaración exacta sobre los nombres de los modelos LLM
1. En el código de producción ([llm_agent.py](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/llm_agent.py#L156-L161)), la función `execute_groq()` define una lista ordenada de modelos candidatos en la API de Groq:
   ```python
   primary_model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
   candidate_models = [primary_model]
   if "llama-3.1-8b-instant" not in candidate_models:
       candidate_models.append("llama-3.1-8b-instant")
   if "openai/gpt-oss-20b" not in candidate_models:
       candidate_models.append("openai/gpt-oss-20b")
   ```
2. **Nunca se ejecutó `llama-3.3-70b-versatile` en los archivos guardados.** Mencionar `llama-3.3-70b-versatile` en el informe previo fue un error de redacción del informe. Los dos experimentos reales guardados en disco son:
   - **Experimento LLM-A (Benchmark Histórico de 100 URLs, `2026-09-30`, `llm_evaluation_results.json`):** Ejecutado con el modelo por defecto `llama-3.1-8b-instant`. De las `100` URLs (`50` phishing, `50` legítimas), `43` descargaron HTML (`html_download_rate = 0.43`) y **`30` completaron la inferencia LLM (`llm_success_rate = 0.30`)** (`12` phishing, `18` legítimas). Ese script histórico no guardó el bloque `usage` ni la latencia de red (`measured_latency_ms: null`), por lo que sus tokens (`estimated_mean_prompt_tokens = 219.4`, `estimated_mean_completion_tokens = 100.6`, `estimated_mean_total_tokens_per_call = 320.0`) están etiquetados explícitamente como `"accounting_mode": "heuristic_string_length_estimate_not_measured"`.
   - **Experimento LLM-B (Evaluación en Vivo sobre las 29 Abstenciones de M5, `2026-10-12`, `llm_live_m5_abstained_results.json`):** Al invocar la API de Groq sobre las `29` muestras de prueba abstenidas por `M5` (`artifacts/m5-real/predictions.csv`), el modelo que respondió efectivamente en la API de Groq y quedó registrado en el campo `"model"` de cada respuesta exitosa y en `"model_queried"` dentro de `llm_evaluation_summary.json` fue **`openai/gpt-oss-20b`**. Completaron con éxito **`7` llamadas en vivo** (todas correspondientes a muestras de phishing abstenidas, `label = 1`) antes de que las `22` restantes fueran rechazadas por límite de tasa de la cuenta gratuita de Groq / inspección SSL local.

### 7.2 Tabla Completa de Resultados y Telemetría del Agente LLM (`llm_evaluation_summary.json`)

| Experimento / Subconjunto en `llm_evaluation_summary.json` | Modelo LLM | $N$ | Umbral $\tau$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR | ROC-AUC | PR-AUC | Brier |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`m0_all`** (Lote histórico completo) | Solo M0 (sin LLM) | 100 | `0.4339` | 49 | 1 | 10 | 40 | `0.890000` | `0.975610` | `0.800000` | **`0.879121`** | `0.020000` | `0.922400` | `0.951348` | `0.085004` |
| **`m0_on_llm_subset`** (Subconjunto con respuesta LLM) | Solo M0 | 30 | `0.4339` | 18 | 0 | 5 | 7 | `0.833333` | `1.000000` | `0.583333` | **`0.736842`** | `0.000000` | `0.888889` | `0.906975` | `0.115168` |
| **`llm_only`** (Subconjunto con respuesta LLM, umbral óptimo) | `llama-3.1-8b-instant` | 30 | `0.1500` | 16 | 2 | 7 | 5 | `0.700000` | `0.714286` | `0.416667` | **`0.526316`** | `0.111111` | `0.821759` | `0.664810` | `0.320820` |
| **`llm_only_fixed_0_5`** (Subconjunto con respuesta LLM, $\tau=0.50$) | `llama-3.1-8b-instant` | 30 | `0.5000` | 17 | 1 | 12 | 0 | `0.566667` | `0.000000` | `0.000000` | **`0.000000`** | `0.055556` | `0.821759` | `0.664810` | `0.320820` |
| **`llm_hybrid`** ($0.65\,p_{M_0} + 0.35\,p_{\text{LLM}}$ con fallback a M0) | `M0` + `llama-3.1-8b-instant` | 100 | `0.4000` | 49 | 1 | 10 | 40 | `0.890000` | `0.975610` | `0.800000` | **`0.879121`** | `0.020000` | **`0.925600`** | `0.949794` | `0.093691` |
| **`cascade_forced_baseline_on_abstained`** (Abstenciones M5 en vivo) | Cascada M5 forzada | 7 | `0.4343` | 0 | 0 | 4 | 3 | `0.428571` | `1.000000` | `0.428571` | **`0.600000`** | `0.000000` | `0.0` *(1 clase)* | `0.0` | `0.395584` |
| **`llm_zero_shot_0_5_on_abstained`** (Abstenciones M5 en vivo) | **`openai/gpt-oss-20b`** | 7 | `0.5000` | 0 | 0 | 2 | 5 | **`0.714286`** | **`1.000000`** | **`0.714286`** | **`0.833333`** | `0.000000` | `0.0` *(1 clase)* | `0.0` | **`0.230614`** |
| **`llm_hybrid_50_50_on_abstained`** ($0.50\,p_{\text{cas}} + 0.50\,p_{\text{LLM}}$) | Cascada + **`openai/gpt-oss-20b`** | 7 | `0.5000` | 0 | 0 | 2 | 5 | **`0.714286`** | **`1.000000`** | **`0.714286`** | **`0.833333`** | `0.000000` | `0.0` *(1 clase)* | `0.0` | `0.280957` |

### 7.3 Telemetría Real Medida vs. Estimación Heurística (`llm_evaluation_summary.json`)

| Métrica de Telemetría y Costo | Evaluación en Vivo sobre Abstenciones M5 ($N = 7$, modelo **`openai/gpt-oss-20b`**, **100 % Medida de API**) | Lote Histórico ($N = 30$, `2026-09-30`, **Estimación Heurística por Longitud de Texto**) |
| :--- | :--- | :--- |
| **Método de contabilización** | `"100% real measured from live Groq API responses"` (`usage.prompt_tokens`, `usage.completion_tokens`) | `"heuristic_string_length_estimate_not_measured"` (`210 + len(url)//3` y `max(48, len(reason)//3 + 35)`) |
| **Tokens de entrada promedio (`mean_prompt_tokens`)** | **`468.0`** (`total_prompt_tokens = 3,276`) | `219.4` (estimado) |
| **Tokens de salida promedio (`mean_completion_tokens`)** | **`795.14`** (`total_completion_tokens = 5,566`) | `100.6` (estimado) |
| **Tokens totales promedio por llamada (`mean_total_tokens_per_call`)** | **`1,263.14`** (`total_tokens_consumed = 8,842`) | `320.0` (estimado) |
| **Latencia de llamada API (`measured_latency_ms`)** | **`Media = 1,809.77 ms`**, `SD = 174.94 ms`, **`P50 = 1,842.73 ms`**, `P90 = 2,028.13 ms`, **`P95 = 2,044.77 ms`**, `P99 = 2,058.08 ms` | `null` (no registrada en el lote histórico) |
| **Costo por 1,000 escalamientos (Tarifa `openai/gpt-oss-20b`: \$0.10/1M in, \$0.50/1M out)** | **`\$0.44437 USD`** (`\$0.018649 USD` por 1,000 URLs totales al `4.1968 %` de abstención de M5) | — |
| **Costo por 1,000 escalamientos (Tarifa `ExecutionBudgetTracker` 8B: \$0.075/1M in, \$0.300/1M out)** | **`\$0.27364 USD`** (`\$0.011484 USD` por 1,000 URLs totales al `4.1968 %` de abstención de M5) | `\$0.04662 USD` (estimado) |

---

## 8. Resolución de la Inconsistencia #5: Hardware Real Verificado y Métricas Exactas de Latencia, Caché, Filtro Bloom y Extensión

### 8.1 Hardware y Entorno Exacto Registrado en los Artefactos
Todos los archivos JSON generados por el pipeline (`evaluation_summary_real.json`, `latency_benchmark_real.json`, `robustness_evaluation_real.json`, `m3_visual_audit_and_authentic_evaluation.json`, `extension_architecture_and_hybrid_evaluation.json` y todos los `manifest.json` de `m0-real` a `m5-real`) contienen el mismo bloque de hardware capturado por `collect_environment_metadata()`:
- **`cpu_model`:** `"13th Gen Intel(R) Core(TM) i5-13600K"`
- **`cpu_physical_cores`:** `14` | **`cpu_logical_cores`:** `20`
- **`ram_total_gb`:** `15.78`
- **`os_system`:** `"Windows"` | **`os_release`:** `"11"` | **`os_version`:** `"10.0.26200"` | **`machine_arch`:** `"AMD64"`
- **`python_version`:** `"3.12.10"` (`CPython`)

### 8.2 Latencias Reales por Componente, Etapa y Cascada (`artifacts/corrected_audit/latency_benchmark_real.json`)

**Script generador:** [benchmark_latency_and_systems.py](file:///d:/Proyects/Seguridad_Informacion/scripts/benchmark_latency_and_systems.py)  
**Memoria pico de inferencia medida (`tracemalloc`):** `640.9 KB` (`peak_inference_memory_kb`).

#### Tabla 8.2A — Latencia en CPU Local y Latencia de Adquisición I/O por Componente (`latency_benchmark_real.json`)

| Categoría / Clave en `latency_benchmark_real.json` | Muestra Evaluada ($N$) | Media (ms) | Desv. Est. (ms) | **Mediana `P50` (ms)** | `P90` (ms) | **`P95` (ms)** | `P99` (ms) | Naturaleza de la Medición |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`stages_local_cpu_ms.M0`** (Extracción + Inferencia CPU M0) | 691 | `17.8780` | `56.7016` | **`16.8930`** | `17.4443` | **`17.5491`** | `17.7845` | 100 % medida en vivo en CPU (`time.perf_counter`) |
| **`stages_local_cpu_ms.M1`** (Extracción + Inferencia CPU M0–M1) | 691 | `33.4076` | `56.8462` | **`33.4437`** | `34.5712` | **`34.7231`** | `35.0223` | 100 % medida en vivo en CPU |
| **`stages_local_cpu_ms.M2`** (Extracción + Inferencia CPU M0–M2) | 691 | `49.0055` | `57.1325` | **`49.8679`** | `51.7112` | **`51.8535`** | `52.4239` | 100 % medida en vivo en CPU |
| **`stages_local_cpu_ms.M3`** (Extracción + Inferencia CPU M0–M3) | 691 | `64.4899` | `57.5896` | **`66.1916`** | `68.7166` | **`68.9416`** | `69.3705` | 100 % medida en vivo en CPU |
| **`M1_dns_tls_http_network_n691`** (Sondeo de red DNS/TLS/HTTP en M1) | 691 | `1,521.9674` | `987.7988` | **`1,272.6515`** | `2,756.0810` | **`3,411.6975`** | `5,018.2697` | 100 % medida en vivo durante adquisición de red |
| **`M2_real_html_dom_parse_n97_previews`** (Parseo DOM HTML real) | 97 | `10.2561` | `14.8185` | **`7.9676`** | `24.1800` | **`42.2540`** | `47.9959` | 100 % medida sobre los 97 archivos HTML en `artifacts/previews/` |
| **`M3_authentic_headless_chrome_cdp_all_n467`** (Captura Chrome CDP real, total) | 467 | `2,251.7319` | `761.5335` | **`2,204.7800`** | `3,349.6560` | **`3,500.1570`** | `3,783.7448` | 100 % medida en vivo con Headless Chrome CDP |
| **`M3_authentic_headless_chrome_cdp_test_n83`** (Captura Chrome CDP real, test) | 83 | `2,237.2268` | `749.4266` | **`2,166.3600`** | `3,297.9020` | **`3,456.0030`** | `3,689.7458` | 100 % medida en vivo con Headless Chrome CDP (partición `test`) |

#### Tabla 8.2B — Latencia End-to-End Acumulada sobre la Cohorte 100 % Auténtica ($N = 83$ test) y sobre `M0–M2` ($N = 691$ test)

| Configuración End-to-End (`latency_benchmark_real.json`) | Cohorte ($N$) | Media (ms) | Desv. Est. (ms) | **Mediana `P50` (ms)** | `P90` (ms) | **`P95` (ms)** | `P99` (ms) | Observaciones |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`M0` E2E (`stages_end_to_end_measured_authentic_n83_ms.M0`)** | 83 | `34.4324` | `162.4274` | **`16.8516`** | `17.3439` | **`17.4678`** | `285.5380` | 100 % real (cohorte CDP test) |
| **`M1` E2E (`stages_end_to_end_measured_authentic_n83_ms.M1`)** | 83 | `1,594.2368` | `1,007.3072` | **`1,235.5163`** | `3,027.5727` | **`3,316.0359`** | `4,924.5251` | 100 % real (CPU + DNS/TLS/HTTP M1) |
| **`M2` E2E (`stages_end_to_end_measured_authentic_n83_ms.M2`)** | 83 | `1,618.5376` | `1,007.3137` | **`1,260.5975`** | `3,052.6794` | **`3,340.5114`** | `4,948.9700` | 100 % real (M1 + parseo DOM real) |
| **`M3` Full Stack E2E (`stages_end_to_end_measured_authentic_n83_ms.M3`)** | 83 | **`3,872.0410`** | `1,241.3555` | **`3,884.0159`** | `5,243.4209` | **`5,743.2570`** | `7,166.1178` | 100 % real (incluye captura Headless Chrome CDP real) |
| **`M5` Cascada Adaptativa E2E (`cascade_m5_authentic_n83_end_to_end_ms`)** | 83 | **`1,071.4397`** | `1,415.9364` | **`499.6368`** | `3,413.5859` | **`4,147.4424`** | `4,934.0510` | **Aceleración `P50 = 7.77x` (`3,884.02 -> 499.64 ms`), reducción media = `72.33 %` (`3.61x`), modalidades promedio = `1.9036` (`-52.41 %`)** |
| **`M0` E2E (`stages_end_to_end_m0_m2_n691_ms.M0`)** | 691 | `17.8780` | `56.7016` | **`16.8930`** | `17.4443` | **`17.5491`** | `17.7845` | 100 % real sobre $N=691$ |
| **`M1` E2E (`stages_end_to_end_m0_m2_n691_ms.M1`)** | 691 | `1,555.3750` | `988.4077` | **`1,296.4710`** | `2,790.4989` | **`3,444.6446`** | `5,048.1290` | 100 % real sobre $N=691$ |
| **`M2` E2E (`stages_end_to_end_m0_m2_n691_ms.M2`)** | 691 | `1,578.9405` | `988.3922` | **`1,320.2599`** | `2,812.9170` | **`3,468.9793`** | `5,071.2254` | 100 % real sobre $N=691$ |
| **Referencia Histórica `M4` / `M5` en $N=691$ (`cascades_stopping_n691_reference`)** | 691 | `941.99` | — | **`620.92`** | `2,435.26` | **`3,188.34`** | `5,018.32` | Parada en $N=691$: `M0=270 (39.07%), M1=254 (36.76%), M2=89 (12.88%), M3=78 (11.29%)`, `avg_modalities = 1.9638` (`-50.9 %`). *(Usa tiempos proxy en muestras M2/M3 sin CDP).* |

#### Tabla 8.2C — Perfiles Operativos SLA sobre la Cohorte 100 % Auténtica ($N = 83$, `sla_profiles` en `latency_benchmark_real.json`)

| Perfil SLA | Presupuesto (`budget_units`) | Umbral Incertidumbre | Modalidades Promedio | Accuracy | Precision | Recall | **F1-Score** | Latencia Media (ms) | **Latencia `P50` (ms)** | Latencia `P90` (ms) | **Latencia `P95` (ms)** | Latencia `P99` (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`real_time_browser`** | `0.0` (Solo M0) | `0.25` | `1.000` | `0.9398` | `0.9600` | `0.8571` | **`0.9057`** | `34.4324` | **`16.8516`** | `17.3439` | **`17.4678`** | `285.5380` |
| **`enterprise_gateway`** | `2.0` (Hasta M2) | `0.15` | `1.783` | `0.9639` | `1.0000` | `0.8929` | **`0.9434`** | `772.6717` | **`499.6368`** | `1,968.9723` | **`3,032.9068`** | `3,814.3799` |
| **`deep_forensic`** | `3.0` (Hasta M3) | `0.001` | `4.000` | `0.9518` | `1.0000` | `0.8571` | **`0.9231`** | `3,872.0410` | **`3,884.0159`** | `5,243.4209` | **`5,743.2570`** | `7,166.1178` |

---

### 8.3 Benchmarks de Filtro Bloom y Caché de Decisiones (`artifacts/corrected_audit/cache_bloom_benchmark.json`)

**Script generador:** [benchmark_latency_and_systems.py](file:///d:/Proyects/Seguridad_Informacion/scripts/benchmark_latency_and_systems.py)  
**Archivo de evidencia:** [cache_bloom_benchmark.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/cache_bloom_benchmark.json).

- **Filtro Bloom (`bloom_filter`):**
  - Elementos insertados (`expected_elements`): **`53,345`** URLs reales de phishing de entrenamiento (`splits/host_unseen.csv`).
  - Configuración: `target_false_positive_rate = 0.001`, `bit_array_size_bits = 766,972`, **`memory_bytes = 95,872` (`93.62 KB`)**, `num_hash_functions = 9`, tiempo total de inserción masiva = **`332.99 ms`**.
  - Evaluación sobre **`14,999`** URLs legítimas no vistas de prueba: **`0` falsos negativos** en entrenamiento, **`12` falsos positivos observados**, **`empirical_false_positive_rate = 0.0008` (`0.08 %`)**.
  - Latencia de búsqueda (`lookup_latency_us`): **`Media = 5.0339 µs`** (`SD = 13.5312 µs`), **`P50 = 4.6 µs`**, `P90 = 5.4 µs`, **`P95 = 5.9 µs`**, `P99 = 7.5 µs`.
- **Caché de Decisiones LRU+TTL (`decision_cache`, carga simulada Zipf sobre implementación real):**
  - Distribución simulada: **`Zipf(alpha=1.15)`**, **`total_requests = 20,000`** sobre un pool de **`2,000`** URLs de prueba (`max_cache_size = 10,000`, `ttl_seconds = 3,600`).
  - Tasa de acierto (`hit_rate`): **`0.92295` (`92.30 %`)** (`hits = 18,459`, `misses = 1,541`).
  - Latencia en acierto (`hit_latency_us`): **`Media = 1.1932 µs`** (`SD = 8.4370 µs`), **`P50 = 1.1 µs`**, `P90 = 1.2 µs`, **`P95 = 1.3 µs`**, `P99 = 1.6 µs`.
  - Latencia en fallo (`miss_latency_us`): **`Media = 1.0488 µs`** (`SD = 0.3855 µs`), **`P50 = 1.0 µs`**, `P90 = 1.1 µs`, **`P95 = 1.2 µs`**, `P99 = 2.22 µs`.

---

### 8.4 Evaluación del Modelo Híbrido de la Extensión (`POST /check`, `HybridM0Model`) sobre $N = 691$

**Script generador:** [evaluate_extension_hybrid.py](file:///d:/Proyects/Seguridad_Informacion/scripts/evaluate_extension_hybrid.py)  
**Archivo de evidencia:** [extension_architecture_and_hybrid_evaluation.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/extension_architecture_and_hybrid_evaluation.json).

| Modo de Evaluación de `HybridM0Model` ($N = 691$ test) | Umbral $\tau$ | TN | FP | FN | TP | Accuracy | Precision | Recall | **F1-Score** | FPR | ROC-AUC | PR-AUC | Brier | ECE | Latencia CPU Local (`Media / P50 / P95`) | Latencia con Red WHOIS+GeoIP en Vivo ($N=16$) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Producción con Escudo Tranco (`production_with_tranco_reputation_shield`)** | `0.50` | 500 | 0 | 41 | 150 | `0.940666` | `1.000000` | `0.785340` | **`0.879765`** (`0.8798`) | `0.0000` | `0.990398` | `0.978559` | `0.071875` | `0.114607` | `16.610 / 16.184 / 22.039 ms` | `Media = 1,523.33 ms`, **`P50 = 685.55 ms`**, `P90 = 2,196.45 ms`, **`P95 = 4,851.23 ms`** |
| **2. Ablación sin Escudo Tranco (`ablation_without_tranco_shield`, $\tau=0.50$)** | `0.50` | 496 | 4 | 39 | 152 | `0.937771` | `0.974359` | `0.795812` | **`0.876081`** (`0.8761`) | `0.0080` | `0.935885` | `0.896039` | `0.081770` | `0.101484` | `16.546 / 15.954 / 21.664 ms` | — |
| **3. Ablación sin Escudo Tranco (`ablation_without_tranco_shield`, $\tau=0.35$)** | `0.35` | 487 | 13 | 35 | 156 | `0.930535` | `0.923077` | `0.816754` | **`0.866667`** (`0.8667`) | `0.0260` | `0.935885` | `0.896039` | `0.081770` | `0.101484` | `16.546 / 15.954 / 21.664 ms` | — |

---

## 9. Matriz Completa de Trazabilidad Científica para Redacción del Artículo en Scopus

Cada fila vincula un resultado científico con su experimento, dataset, partición, protocolo, archivo de predicciones, archivo de métricas y script generador:

| ID | Experimento / Tabla Científica | Dataset y Versión | Partición y Cohorte ($N$) | Protocolo y Umbral | Archivo de Predicciones (`predictions.csv`) | Archivo de Métricas / Resumen JSON | Script Generador |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E1** | Corpus Canónico y Particiones | `data/processed/0.1.0/samples.csv` (`0.1.0`, $N=176,201$) | `conventional` ($176,201$), `host_unseen` ($176,201$), `temporal` ($176,201$), `temporal_host_unseen` ($173,633$) | Deduplicado por hash canónico y disjunto por dominio/tiempo | N/A (Definición de particiones en `splits/*.csv`) | `data/processed/0.1.0/statistics.json`<br>`data/processed/0.1.0/manifest.json` | `src/phishguard_data/cli.py`<br>`scripts/create_temporal_split.py` |
| **E2** | Baseline Léxico M0 sobre Corpus Completo (Host-Unseen y Temporal) | `samples.csv` ($N=176,201$ / $173,633$) | `host_unseen` ($N_{\text{test}}=26,430$)<br>`temporal` ($N_{\text{test}}=17,625$)<br>`temporal_host_unseen` ($N_{\text{test}}=16,484$) | `authority_only` (11 vars), `selected_threshold` y `threshold_0_5` | `artifacts/url-baseline-0.2.0/predictions.csv`<br>`artifacts/m0-temporal/predictions.csv`<br>`artifacts/m0-temporal-host-unseen/predictions.csv` | `artifacts/url-baseline-0.2.0/metrics.json`<br>`artifacts/m0-temporal/metrics.json`<br>`artifacts/m0-temporal-host-unseen/metrics.json` | `src/phishguard_ml/cli.py`<br>`scripts/train_m0_temporal.py` |
| **E3** | Modelos Multimodales de Etapa Única (`M0–M3`) y Cascadas (`M4_fixed`, `M4`, `M5`) en Complete-Case | `samples.csv` + `*-results-real.jsonl` ($N_{\text{CC}}=5,612$) | `host_unseen` Complete-Case (`train=4,219`, `val=702`, `test=691`: 500 legit, 191 phish) | `selected_threshold` ($\tau^*$), `fixed_0_5`, `low_fpr_threshold`, y selectivo ($N=662$, $H_{\text{abs}}=0.50$) | `artifacts/m0-real/predictions.csv`<br>`artifacts/m1-real/predictions.csv`<br>`artifacts/m2-real/predictions.csv`<br>`artifacts/m3-real/predictions.csv`<br>`artifacts/m4-fixed-real/predictions.csv`<br>`artifacts/m4-real/predictions.csv`<br>`artifacts/m5-real/predictions.csv` | `artifacts/m0-real/metrics.json` ... `artifacts/m5-real/metrics.json`<br>`artifacts/corrected_audit/evaluation_summary_real.json`<br>`artifacts/corrected_audit/evaluation_report_real.csv` | `scripts/train_and_evaluate_all_real.py`<br>`scripts/update_corrected_summaries.py` |
| **E4** | Modelos Multimodales (`M0–M5`) en Intention-to-Evaluate (`ITE`) | `samples.csv` + `*-results-real.jsonl` ($N_{\text{ITE}}=10,000$) | `host_unseen` ITE (`train=7,001`, `val=1,499`, `test=1,500`: 851 legit, 649 phish) | Imputación explícita con banderas `*_observation_available`, `selected_threshold` | `artifacts/m0-ite-real/predictions.csv`<br>`artifacts/m1-ite-real/predictions.csv`<br>`artifacts/m2-ite-real/predictions.csv`<br>`artifacts/m3-ite-real/predictions.csv` | `artifacts/m0-ite-real/metrics.json` ... `artifacts/m3-ite-real/metrics.json`<br>`artifacts/corrected_audit/evaluation_summary_real.json` | `scripts/train_and_evaluate_all_real.py` |
| **E5** | Evaluación Visual 100 % Chrome CDP Real (`M0–M3`) y Cascada 3 Etapas `M0->M2` | `visual-results-authentic-cdp.jsonl` ($N=467$ `live_cdp`) | `host_unseen` CDP Real (`train=313`, `val=71`, `test=83`: 55 legit, 28 phish) y CC ($N_{\text{test}}=691$) | 100 % capturas Chrome CDP reales (`live_cdp`), sin diagramas PIL sintéticos | `artifacts/corrected_audit/m3-authentic-cdp/predictions.csv` | `artifacts/corrected_audit/m3-authentic-cdp/metrics.json`<br>`artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json` | `scripts/audit_and_capture_authentic_m3.py`<br>`scripts/sync_and_enrich_audit_artifacts.py` |
| **E6** | Pruebas Estadísticas Pareadas (Bootstrap $B=1,000$, McNemar, Holm-Bonferroni) | Cohorte Complete-Case ($N_{\text{test}}=691$) | `host_unseen` CC: Cobertura Forzada ($N=691$) y Subconjunto Decidido por M5 ($N=662$) | 100 % libre de filtración de etiquetas (`predict_all_models_label_blind`) | `artifacts/m0-real/predictions.csv` ... `artifacts/m5-real/predictions.csv` | `artifacts/corrected_audit/statistical_comparisons_all.json`<br>`artifacts/corrected_audit/statistical_comparisons_all.csv` | `scripts/evaluate_robustness_and_stats.py` |
| **E7** | Robustez Adversarial en Espacio de Características (6 Familias de Ataque) | Subconjunto de Phishing de Prueba ($N_{\text{phish}}=191$, $N_{\text{legit}}=500$) | `host_unseen` CC ($N=691$) | Perturbación paramétrica `perturb_feature_matrix`, 100 % ciega a `y_test` | `artifacts/m0-real/predictions.csv` ... `artifacts/m5-real/predictions.csv` | `artifacts/corrected_audit/robustness_evaluation_real.json`<br>`artifacts/corrected_audit/robustness_evaluation_real.csv` | `scripts/evaluate_robustness_and_stats.py` |
| **E8** | Benchmarks de Latencia (CPU, Red M1, Parseo DOM M2, Chrome CDP M3, Cascadas y SLA) | Cohorte CC ($N=691$), Previews HTML ($N=97$) y Cohorte CDP ($N=467 / N=83$) | `host_unseen` CC ($N=691$) y CDP Test ($N=83$) | Medición de reloj real (`perf_counter`) sin fórmulas sintéticas en `stages_end_to_end_measured_authentic_n83_ms` | `artifacts/m4-real/stage_stopping_distribution.json`<br>`artifacts/m5-real/stage_stopping_distribution.json` | `artifacts/corrected_audit/latency_benchmark_real.json` | `scripts/benchmark_latency_and_systems.py` |
| **E9** | Benchmarks de Filtro Bloom y Caché de Decisiones LRU+TTL | `53,345` URLs phish (`train`) vs `14,999` legit (`test`); `20,000` consultas `Zipf(1.15)` | `host_unseen` | Microbenchmark en memoria sobre implementaciones reales `BloomFilter` y `DecisionCache` | N/A | `artifacts/corrected_audit/cache_bloom_benchmark.json` | `scripts/benchmark_latency_and_systems.py` |
| **E10** | Evaluación del Agente LLM (Histórico $N=100$ y En Vivo sobre Abstenciones M5 $N=29 \to 7$) | Subconjunto estratificado ($N=100$) y Abstenciones de M5 ($N=29$) | `host_unseen` | Histórico (`llama-3.1-8b-instant`, $n=30$) y En Vivo (`openai/gpt-oss-20b`, $n=7$ con telemetría real de API) | `artifacts/corrected_audit/llm_evaluation_results.json`<br>`artifacts/corrected_audit/llm_live_m5_abstained_results.json` | `artifacts/corrected_audit/llm_evaluation_summary.json` | `scripts/evaluate_llm.py` |
| **E11** | Auditoría Arquitectónica y Evaluación de la Extensión (`POST /check`, `HybridM0Model`) | Cohorte CC ($N_{\text{test}}=691$) y Sondeo en Vivo WHOIS+GeoIP ($N=16$) | `host_unseen` CC ($N=691$) | Con y sin escudo Tranco Top-1M ($\tau=0.50$ y $\tau=0.35$) | N/A | `artifacts/corrected_audit/extension_architecture_and_hybrid_evaluation.json` | `scripts/evaluate_extension_hybrid.py` |
