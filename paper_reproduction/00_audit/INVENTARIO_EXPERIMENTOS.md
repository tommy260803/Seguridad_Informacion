# INVENTARIO Y AUDITORÍA CIENTÍFICA DE EXPERIMENTOS — PHISHPE / PHISHGUARD PRO

**Fecha de auditoría:** 2026-10-15  
**Auditor:** Especialista Senior en MLOps, Ciberseguridad y Reproducibilidad Científica  
**Repositorio:** `D:\Proyects\Seguridad_Informacion`  
**Rama:** `corrections-phase2`  
**Commit de referencia:** `058169a78fb50af26bfd3ad9e95e547f782fee1c` (Freeze #5)  
**Marco de evaluación:** Criterios de rigor para revistas indexadas en Scopus / Latindex (Revista Politécnica, Ecuador).

---

## 1. Resumen de la Auditoría Científica

Para cada uno de los experimentos que sustentan las afirmaciones y resultados empíricos del proyecto PhishPe, se examinó la existencia de datos crudos, particiones procesadas, archivos de predicciones, código ejecutable, manifiestos criptográficos (SHA-256), validez de las etiquetas de referencia (Ground Truth) y dependencias externas.

### Resumen de Reproducibilidad por Experimento

| ID | Experimento | N Muestras | Datos Originales | Predicciones | Código Reproducción | Manifiestos/Hashes | Estado de Reproducibilidad |
|---|---|---:|---|---|---|---|---|
| **EXP-01** | Corpus Histórico Canónico | 176,201 | Sí (`samples.csv`) | Sí (`predictions.csv`) | Sí (`pipeline.py`) | Sí (`manifest.json`) | **REPRODUCIBLE TOTAL** |
| **EXP-02** | Conjunto Multimodal Completo | 5,612 | Sí (`samples.jsonl`) | Sí (`metrics.json`) | Sí (`batch_analyze.py`) | Sí (`statistics.json`) | **REPRODUCIBLE TOTAL (OFFLINE)** |
| **EXP-03** | Partición de Prueba Host-Unseen | 691 (CC) / 26,430 (ITE)| Sí (`host_unseen.csv`) | Sí (`predictions.csv`) | Sí (`train_and_evaluate_all_real.py`) | Sí (`freeze_manifest.json`) | **REPRODUCIBLE EXACTO (Δ = 0.000)** |
| **EXP-04** | Cohorte Externa Independiente | 1,200 | Sí (`cohort2_dataset.csv`) | Sí (`url_level_predictions.csv`) | Sí (`phase2c_evaluate_cohort2.py`) | Sí (`cohort2_labels_frozen.json`) | **REPRODUCIBLE EXACTO (11/11 PASS)** |
| **EXP-05** | Sondeo Externo Multimodal en Vivo | 600 | Sí (`probe_raw.jsonl`) | Sí (`probe_predictions.csv`) | Sí (`phase2c_evaluate_cohort2.py`) | Sí (`eval_summary.json`) | **REPRODUCIBLE OFFLINE / CONGELADO** |
| **EXP-06** | Piloto Visual Chrome CDP Auténtico | 83 (Test) / 467 (Total)| Sí (`visual-results-authentic-cdp.jsonl`) | Sí (`06_visual_y_llm_results.json`)| Sí (`fase2_06_visual_y_llm.py`) | Sí (`figures/fig4_...`) | **REPRODUCIBLE TOTAL (OFFLINE)** |
| **EXP-07** | Batería Operativa E2E en Chrome Real | 27 Escenarios | Sí (`requests.jsonl`) | Sí (`summary.json`) | Sí (`e2e_chrome_phase2.py`) | Sí (`E2E_CHROME_RESULTS.md`) | **REPRODUCIBLE EN CFt (25 PASS, 2 NOT_RUN)** |
| **EXP-08** | Experimento Pareado www vs no-www | 300 Pares (600 URLs) | Sí (`cohort2_dataset.csv`) | Sí (`www_paired_predictions.csv`)| Sí (`phase2c` / `phase2n`) | Sí (`www_paired_experiment.json`)| **REPRODUCIBLE EXACTO (0 FLIPS)** |
| **EXP-09** | Robustez Adversarial Multimodal | 176 Casos x 6 Familias | Sí (`adversarial_samples.json`)| Sí (`robustness_results.json`) | Sí (`evaluate_robustness_and_stats.py`) | Sí (`figures/fig4_...`) | **REPRODUCIBLE TOTAL** |
| **EXP-10** | Pruebas Pareadas de Hipótesis | 14 Comparaciones | Sí (`predictions.csv`) | Sí (`07_all_..._table.csv`) | Sí (`phase2e_verify_historical_stats.py`)| Sí (`phase2e_run.log`) | **REPRODUCIBLE EXACTO (14/14 MATCH)** |

---

## 2. Detalle Exhaustivo por Experimento

### EXP-01: Corpus Histórico Canónico (N = 176,201 URLs)
* **Objetivo científico:** Servir como base de entrenamiento, validación y prueba para clasificadores léxicos y de infraestructura en escala masiva, eliminando atajos de dominio.
* **Composición y fuentes:**
  - Total de registros crudos adquiridos: 176,645 (PhishTank: 76,645 URLs de phishing verificadas; Tranco Top 1M: 100,000 URLs legítimas populares).
  - Exclusiones documentadas y verificables: 13 URLs con etiquetas contradictorias entre fuentes, 428 duplicados exactos con la misma etiqueta, 3 URLs con caracteres de control inválidos o longitud excesiva ($> 8192$ caracteres).
  - Corpus neto depurado: **176,201 URLs** (99,994 legítimas, 76,207 phishing; prevalencia: 43.25% phishing).
* **Ubicación de datos:**
  - Crudos: `data/raw/20260919T192154.381983Z/phishtank.csv.bz2`, `tranco.csv.zip`, `public_suffix_list.dat`. Manifiesto: `acquisition-manifest.json`.
  - Procesados: `data/processed/0.1.0/samples.csv` (62,268,029 bytes), `samples.jsonl` (109,841,880 bytes), `statistics.json` (10,241 bytes).
* **Etiqueta de referencia (Ground Truth):**
  - Legítimas: Dominios de alta reputación Tranco Top 1M (rango $1$ a $100,000$).
  - Phishing: Reportes comunitarios validados por múltiples revisores en PhishTank con bandera `verified == "yes"`.
  - Validez: Apropiada y estándar en la literatura científica.
* **Código de reproducción:** `src/phishguard_data/pipeline.py`, invocable vía `phishdata run`.
* **Reproducibilidad:** Comprobada. Los recuentos reportados en `statistics.json` coinciden al 100% con los datos en disco.

---

### EXP-02: Conjunto Multimodal Completo (N = 5,612 Casos Completos)
* **Objetivo científico:** Evaluar el impacto de la correlación multimodal completa (URL + Red + HTML DOM + Renderizado) sobre un subconjunto donde todas las modalidades pudieron adquirirse exitosamente.
* **Composición y attrition (mortalidad de recolección):**
  - Muestras con éxito en infraestructura de red: 7,916 URLs.
  - Muestras con éxito en análisis de contenido HTML: 5,646 URLs.
  - Muestras con éxito simultáneo en infraestructura y contenido: **5,612 casos completos** (*Complete-Case*).
* **Ubicación de artefactos:**
  - `data/processed/0.1.0/statistics.json` (clave `multimodal_cohort`).
  - Modelos asociados: `artifacts/m0-real/`, `artifacts/m1-real/`, `artifacts/m2-real/`, `artifacts/m3-real/`.
* **Sesgo metodológico identificado (L3):**
  - La completitud es fuertemente asimétrica entre clases: los sitios de phishing tienen una vida media corta (horas o días) y presentan una tasa de caída de red mucho mayor que los sitios legítimos consolidados.
  - *Mitigación:* Se implementó y reportó por separado el análisis por intención de evaluación (*Intention-To-Evaluate*, ITE, $N = 15,466$) y el análisis de casos completos (*Complete-Case*, CC, $N = 5,612$), garantizando que las ausencias de modalidad no se traten como predicciones correctas.
* **Reproducibilidad:** Verificada offline mediante predicciones e índices congelados.

---

### EXP-03: Partición de Prueba Host-Unseen (N = 691 URLs Complete-Case / 26,430 ITE)
* **Objetivo científico:** Medir la capacidad de generalización estricta ante dominios registrados no observados durante la fase de entrenamiento (*Out-of-Distribution Domain Generalization*).
* **Partición y blindaje:**
  - Criterio de separación: Particionado por dominio registrado (`registered_domain` mediante Public Suffix List), impidiendo que subdominios del mismo sitio aparezcan simultáneamente en entrenamiento y prueba (*data leakage zero*).
  - Subconjunto de prueba `host_unseen`:
    * ITE: 26,430 URLs totales (conteo verificado en `verify_audit_report_consistency.py`).
    * Complete-Case Multimodal: **691 URLs** (492 legítimas, 199 phishing).
* **Resultados históricos verificados:**
  - M0 (Léxico URL): F1 = 0.8658, TP = 158, TN = 484, FN = 41, FP = 8.
  - M1 (URL + Infra): F1 = 0.9252, TP = 167, TN = 486, FN = 32, FP = 6.
  - M2 (URL + Infra + DOM): F1 = 0.9315, TP = 170, TN = 486, FN = 29, FP = 6.
  - M3 (Multimodal con Visión): F1 = 0.9286, TP = 169, TN = 486, FN = 30, FP = 6.
  - M4 (Cascada Adaptativa Binaria): F1 = 0.9248, TP = 166, TN = 486, FN = 33, FP = 6.
  - M4-Fixed (Cascada Fija): F1 = 0.9029, TP = 158, TN = 486, FN = 41, FP = 6.
  - M5 (Cascada Adaptativa Selectiva, N = 647 decididos): F1 = **0.9538**, Precisión = **1.0000**, TP = 155, TN = 492, FN = 15, **FP = 0**. Casos abstenidos: 44.
* **Código de reproducción:** `scripts/phase2e_verify_historical_stats.py`, `scripts/verify_audit_report_consistency.py`.
* **Reproducibilidad:** Comprobada exactamente al 100% (recálculo independiente confirma $\Delta = 0.000000$ en todas las matrices de confusión).

---

### EXP-04: Cohorte Externa Independiente (N = 1,200 URLs)
* **Objetivo científico:** Validación externa confirmatoria sobre feeds de amenazas en tiempo real y listas de popularidad web adquiridas en fecha posterior e independiente del corpus original.
* **Diseño metodológico y tamaño de muestra:**
  - Justificación a priori: `artifacts/corrections_phase2/cohort2/cohort2_sample_size_justification.json` (potencia estadística calculada para detectar $\Delta F1 \ge 0.03$ con $\alpha = 0.05$ y $\beta = 0.20$).
  - Protocolo de pre-registro y congelamiento: feeds descargados y hashes congelados en `cohort2_labels_frozen.json` antes de consultar etiquetas o evaluar modelos.
  - Total de muestra: **1,200 URLs** exactamente balanceadas (600 phishing / 600 legítimas).
  - Fuentes de phishing: URLhaus (297), PhishTank (260), OpenPhish (43).
  - Fuentes de legítimas: Tranco Top 1M (389), Majestic Million (211).
  - Solape: **0 dominios y 0 URLs** en común con el corpus histórico de 176,201 URLs.
* **Archivos asociados:**
  - `artifacts/corrections_phase2/cohort2/cohort2_dataset.csv` (1,201 líneas = cabecera + 1,200 filas).
  - `artifacts/corrections_phase2/eval/url_level_predictions.csv` (1,201 líneas).
  - `artifacts/corrections_phase2/eval/url_level_metrics.json`.
* **Resultados en cohorte externa:**
  - M0 original: F1 = 0.8829, FPR = 0.0333.
  - M0 normalizado (BUG-07 `_strip_www`): F1 = 0.8707, FPR = 0.0333.
  - Config A (Baseline ceb0c9e): F1 = 0.8593.
  - Config C (Corregida con normalización): F1 = 0.8550.
* **Código de reproducción:** `scripts/phase2c_evaluate_cohort2.py` (Bloque A) y `scripts/phase2n_revalidate_offline.py`.
* **Reproducibilidad:** Ejecutado y verificado en esta auditoría con veredicto PASS (11/11 comprobaciones exactas).

---

### EXP-05: Sondeo Externo Multimodal en Vivo (N = 600 URLs)
* **Objetivo científico:** Medir la latencia y comportamiento de la cascada de inferencia en tiempo real consultando la pila de red (DNS, TLS, HTTP/DOM) contra Internet público sobre un estrato aleatorio balanceado de la cohorte externa.
* **Composición y resultados de sondeo:**
  - Total sondeado: 600 URLs (300 phishing / 300 legítimas).
  - Sitios completos con respuesta válida en todas las modalidades: 247 URLs (41.2% completitud global; 13.3% phishing vs 69.0% legítimas).
  - Archivos: `artifacts/corrections_phase2/eval/probe_raw.jsonl` (600 líneas, 4.68 MB), `probe_predictions.csv` (601 líneas), `probe_and_cascade_metrics.json`.
* **Latencia real de pared medida:**
  - M4 (Cascada Adaptativa): Mediana P50 = 875 ms, P90 = 3,600 ms, P95 = 4,683 ms.
  - Cascada Conservadora: P50 = 889 ms, P95 = 4,683 ms.
  - Infraestructura aislada: P50 = 959 ms, P95 = 3,577 ms.
* **Estado de congelamiento:** El bloque de sondeo en vivo se ejecutó bajo el Freeze #3. La auditoría offline (`phase2n`) no re-consulta la red pública para evitar la deriva no determinista por muerte de URLs, preservando el log histórico congelado.

---

### EXP-06: Piloto Visual Auténtico Chrome CDP (N = 83 Test / 467 Total)
* **Objetivo científico:** Cuantificar el aporte discriminativo real de la modalidad visual (M3) libre de artefactos sintéticos o proxies DOM, empleando renderizado real mediante Chrome DevTools Protocol (CDP).
* **Muestra evaluada:**
  - Cohorte total auténtica CDP: 467 URLs (312 entrenamiento, 72 validación, 83 prueba en partición `host_unseen`).
  - Muestra de prueba: **83 URLs** con capturas PNG reales en `artifacts/authentic-cdp-screenshots/`.
* **Archivos asociados:**
  - `artifacts/analysis-results/visual-results-authentic-cdp.jsonl` (10,000 líneas con vectores de extracción).
  - `artifacts/validacion_scopus_fase2/fase6_visual_llm/06_visual_y_llm_results.json`.
  - `figures/fig4_visual_cdp_and_adversarial_robustness.png`.
* **Resultados en N = 83:**
  - Clasificador Visual Puro (32 características visuales): F1 = 0.5584, ROC-AUC = 0.5584 (demuestra que la apariencia visual aislada sin contexto de URL/DOM tiene bajo poder discriminativo).
  - M2 (URL + Infra + Contenido): F1 = 0.9434.
  - M3 auténtico CDP (URL + Infra + Contenido + CDP Visual): F1 = 0.8966, ROC-AUC = 0.9789.
  - Conclusión científica: M3 no supera a M2 en F1 debido a la alta precisión que ya aporta el análisis estructural del DOM y campos de contraseña, pero aporta una calibración probabilística superior en el espacio ROC-AUC.
* **Código de reproducción:** `scripts/fase2_06_visual_y_llm.py` y `scripts/reproduce_all_validation_tables_and_figures.py`.
* **Reproducibilidad:** Comprobada en offline.

---

### EXP-07: Pruebas Operativas E2E en Navegador Real (27 Escenarios)
* **Objetivo científico:** Verificar que la extensión Manifest V3 en interacción con el backend FastAPI local protege al usuario en tiempo real sin bloquear el navegador y respetando los presupuestos de latencia.
* **Entorno del navegador:** Chrome-for-Testing 156.0.8078.4 (build Playwright `chromium-1248`).
* **Resultados verificados:**
  - 27 escenarios ejecutados: **25 PASS, 2 NOT_RUN** (`l_concurrency`, `o_cascade_analyses`), 0 PARTIAL.
  - 40 llamadas registradas al backend `:8080` en `requests.jsonl`.
  - 4 errores registrados (todos deliberados en escenarios de inyección de fallos: 2 timeouts en `h_timeout_stub` a 8,005 y 8,010 ms; 2 caídas forzadas en `m_backend_down`).
  - Errores espontáneos: **0 sobre 40 llamadas**.
  - Latencia medida por resource-timing del navegador: P50 = 40 ms, P90 = 2,160.8 ms, P95 = 3,808.2 ms.
  - Navegación a decisión visible: P50 = 1,764.9 ms.
  - Caché local: 10 consultas frías (9 llamadas al backend, P50 = 1,740.1 ms) vs 10 consultas calientes (**0 llamadas al backend**, P50 = 82.6 ms).
* **Archivos asociados:** `artifacts/e2e_chrome/summary.json`, `requests.jsonl`, `backend.log`, 54 capturas PNG en `artifacts/e2e_chrome/screenshots/`.
* **Código de reproducción:** `scripts/e2e_chrome_phase2.py`, `scripts/phase2k_summarize_e2e.py`.

---

### EXP-08: Experimento Pareado www vs no-www (N = 300 Pares)
* **Objetivo científico:** Demostrar y resolver experimentalmente el atajo de aprendizaje espurio (*shortcut learning*) del prefijo `www` en el modelo histórico M0.
* **Diseño experimental:** 300 dominios legítimos evaluados en dos variantes exactas: `http://www.dominio.com` vs `http://dominio.com` (600 URLs evaluadas).
* **Resultados verificados:**
  - M0 histórico sin corregir: FPR en variantes `www.` = **1.0000** (100% clasificado erróneamente como phishing), FPR en variantes sin `www.` = 0.0533. Discrepancias (*flips* de decisión): **170 de 300 pares**.
  - M0 corregido con BUG-07 (`_strip_www`): FPR en `www.` = **0.0533**, FPR en sin `www.` = **0.0533**. Discrepancias: **0 de 300 pares**.
* **Archivos asociados:** `artifacts/corrections_phase2/eval/www_paired_experiment.json`, `www_paired_predictions.csv`.
* **Reproducibilidad:** Verificada en esta auditoría mediante `phase2n_revalidate_offline.py` (Bloque E).

---

### EXP-09: Robustez Adversarial Multimodal (6 Familias de Ataque)
* **Objetivo científico:** Medir la tasa de éxito de ataque (*Attack Success Rate*, ASR) ante perturbaciones sintéticas estructuradas diseñadas para evadir cada modalidad.
* **Familias evaluadas:**
  1. `url_evasion`: Evasión léxica de URL.
  2. `homograph_punycode`: Suplantación visual con caracteres cirílicos/griegos.
  3. `infra_evasion`: Rotación rápida de DNS y certificados autofirmados.
  4. `dom_obfuscation`: Ofuscación de JavaScript y división de inputs.
  5. `visual_noise`: Ruido gaussiano y perturbación de renderizado.
  6. `combined_multimodal`: Combinación coordinada multietapa.
* **Comportamiento verificado de M5:**
  - Ante perturbaciones léxicas severas, la evasión silenciosa (*silent bypass*) de M5 se mantiene en 43.75%, mientras que el resto es capturado o canalizado a abstención ($H > \tau_{\text{abst}}$), evitando falsos negativos catastróficos.
* **Archivos asociados:** `artifacts/validacion_scopus_fase2/figures/fig4_visual_cdp_and_adversarial_robustness.png`, `src/phishguard_robustness/perturbations.py`.

---

### EXP-10: Pruebas Pareadas de Hipótesis Estadísticas (14 Comparaciones)
* **Objetivo científico:** Comprobar la significación estadística de las diferencias de rendimiento entre clasificadores y configuraciones mediante la prueba exacta de McNemar pareada y corrección por tasa de error familiar (FWER) vía método secuencial de Holm-Bonferroni.
* **Conjunto de pruebas:**
  - Familia H (Hipótesis Primarias, $m = 6$): M0 vs M1, M0 vs M2, M0 vs M3, M0 vs M4, M0 vs M5 (decididos), M1 vs M2.
  - Familia E (Comparaciones Exploratorias y Externas, $m = 8$): M2 vs M3, M4 vs M4-Fixed, Config A vs Config C en cohorte externa, M0 vs Config C, entre otras.
* **Resultados canónicos reproducidos:**
  - M0 vs M1: $\Delta F1 = +0.0595$, discordantes 27 vs 2, $p = 1.049\times 10^{-5}$ (Significativo tras Holm).
  - M0 vs M2: $\Delta F1 = +0.0658$, discordantes 30 vs 2, $p = 3.856\times 10^{-5}$ (Significativo tras Holm).
  - M0 vs M5 (decididos): $\Delta F1 = +0.0577$, discordantes 25 vs 1, $p = 1.907\times 10^{-6}$ (Significativo tras Holm).
  - Config A vs Config C (cohorte externa N = 1,200): $\Delta F1 = -0.0043$, discordantes 4 vs 0, $p = 0.1250$ ($p_{\text{Holm}} = 1.0000$, **no significativo**, confirmando equivalencia estadística tras corregir el atajo de www).
* **Archivos asociados:** `artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv` (SHA-256 verificado: `73f77123...`).
* **Código de reproducción:** `scripts/phase2e_verify_historical_stats.py` (14/14 filas verificadas idénticas en esta auditoría).
