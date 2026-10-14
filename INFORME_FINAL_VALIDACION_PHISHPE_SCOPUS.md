# INFORME FINAL DE VALIDACIÓN CIENTÍFICA AVANZADA DE PHISHPE (PHISHGUARD) PARA REVISTA POLITÉCNICA (SCOPUS)

**Fecha de cierre de auditoría:** 2026-10-13 UTC  
**Repositorio:** `d:\Proyects\Seguridad_Informacion`  
**Rama experimental dedicada:** `experimental/validacion-scopus-fase2`  
**Commit base inmutable:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Entorno verificado:** Python `3.12.10` (CPython), Windows 11 (`10.0.26200` AMD64), Intel Core i5-13600K (14 núcleos físicos / 20 lógicos), `scikit-learn 1.7.2`, `numpy 2.4.6`, `scipy 1.15.3`, Google Chrome `146.0.7680.178`, `SEED = 42`.  
**Estado de los manuscritos originales:** `PhishPe_Article_APA7.docx` y `PhishGuard_Article_APA7.docx` **intactos (no modificados)**.

---

## 1. Resumen Ejecutivo de los Cinco Objetivos Científicos

Esta fase de validación experimental independiente se diseñó y ejecutó sin buscar inflar artificialmente las métricas, sino para determinar con rigor estadístico y trazabilidad criptográfica **cómo funciona PhishPe, cuándo funciona y cuándo falla**:

1. **Generalización ante datos verdaderamente independientes (Fase II, [`02_VALIDACION_EXTERNA.md`](file:///d:/Proyects/Seguridad_Informacion/02_VALIDACION_EXTERNA.md)):**
   - Se construyó un nuevo conjunto externo de **$N = 1,054$ URLs verificadas** (`600` phishing de `OpenPhish`, `CERT.PL` y `Phishing.Army`; `454` legítimas de `Majestic Million`, `Hipo Universities` y `CISA .gov`) tras auditar `3,680` candidatos y excluir `2,606` dominios que solapaban con los `68,539` dominios registrados de `samples.csv` (**`0.0%` de contaminación por dominio registrado PSL**).
   - Se descubrió y demostró empíricamente un **sesgo de formato del prefijo `www.`** en el dataset `0.1.0`: como las URLs benignas de Tranco en `samples.csv` se construyeron sin `www.` (`subdomain_count = 0`), el modelo `M0` congelado interpreta el prefijo `www.` de sitios universitarios externos (`http://www.espol.edu.ec/`) como un subdominio sospechoso (`FPR = 94.0%` en `Hipo Universities`, `ROC-AUC = 0.4859` global en URLs crudas).
   - Al aplicar la normalización canónica `strip_www()` **sin reentrenar ni modificar ningún peso de los modelos congelados**, la FPR externa de `M0` cae de **`46.70%` a `9.69%`** y su `ROC-AUC` sube de **`0.4859` a `0.7530`** (`PR-AUC = 0.8135`). En el subconjunto multimodal en vivo ($N_{\text{CC}} = 104$), los modelos congelados exhiben una mejora monótona: `M0` (`ROC-AUC = 0.7057`) $\rightarrow$ `M1` (`ROC-AUC = 0.8263`) $\rightarrow$ **`M2` (`ROC-AUC = 0.9248`, `PR-AUC = 0.9423`, `Precision = 96.30%`, `FPR = 2.00%`)**.
   - El modelo de producción de la extensión (`HybridM0Model`) alcanza en datos externos **`ROC-AUC = 0.8077` (`PR-AUC = 0.8712`, `Precision = 97.13%`, `FPR = 1.32%`)** con Tranco y **`ROC-AUC = 0.7710` (`F1 = 0.5844`, `FPR = 2.20%`)** sin Tranco, sin requerir `strip_www()`.
2. **Contribución frente a métodos alternativos y prueba de la paradoja de URL completa (Fase IV, [`04_COMPARACION_CIENTIFICA.md`](file:///d:/Proyects/Seguridad_Informacion/04_COMPARACION_CIENTIFICA.md)):**
   - Se entrenaron y evaluaron 8 baselines de literatura sobre las mismas particiones (`train = 4,219`, `val = 702`, `test = 691`) y sobre el conjunto externo ($N = 1,054$).
   - Se demostró empíricamente por qué los clasificadores de URL completa (`Baseline1A_FullURL36_RF`, `Baseline1B_FullURL36_HGB`, `Baseline2B_CharNgram_FullURL_LR`) aparentan alcanzar `F1 = 0.949–0.989` en el test interno (explotando el atajo de que Tranco tiene rutas vacías `/` y PhishTank rutas largas), pero **colapsan en la cohorte externa (`ROC-AUC = 0.4749–0.6730`)**, donde son ampliamente superados por `PhishPe_M0` (`ROC-AUC = 0.7530`) y `HybridM0Model` (`ROC-AUC = 0.8077`).
   - A igualdad de alcance léxico (solo hostname), `PhishPe_M2` (`F1 = 0.9315`) y `PhishPe_M4` (`F1 = 0.9248`) superan de forma altamente significativa al modelo TF-IDF de 15,000 n-gramas de caracteres `Baseline2A_CharNgram_HostOnly_LR` (`F1 = 0.8480`, McNemar $p = 1.0 \times 10^{-6}$ y $3.0 \times 10^{-6}$), y añadir las 23 variables de infraestructura en `M2` reduce los falsos positivos en un **`60%–80%`** frente a los clasificadores monolíticos URL + HTML DOM sin infraestructura (`Baseline3A/3B`).
3. **Rendimiento real de la extensión y auditoría de software (Fase III, [`03_EXTENSION_REAL.md`](file:///d:/Proyects/Seguridad_Informacion/03_EXTENSION_REAL.md)):**
   - Se evaluaron contra un servidor `uvicorn` real las tres configuraciones: **Configuración A** (`POST /check`, `HybridM0Model`), **Configuración B** (`/analyze/cascade`) y **Configuración C** (integración experimental `HybridM0 -> M1 -> M2/M5`).
   - Se descubrieron **6 defectos operativos reales en el código** (Bugs 1–6), incluyendo un desajuste de timeout cliente/servidor (`6,000 ms` en `background.js` frente a `8,000 ms` en hilos WHOIS/GeoIP del backend que provoca un `5.0%` de abortos fail-open en caché fría, donde $P_{50} = 994.45\text{ ms}$ y $P_{99} = 9,520.85\text{ ms}$, frente a $P_{50} = 17.11\text{ ms}$ en caché cálida) y un bug de clave JSON + falta de decodificación Punycode (`xn--`) que desactiva el override de homógrafos en producción.
   - La **Configuración C** resuelve el `73.81%` de las peticiones en la Etapa 0 con una latencia mediana de **$51.51\text{ ms}$** ($23.4\times$ más rápida que la cascada API pura `Config B`), logrando `F1 = 0.9178`, `Precision = 100%` y `FPR = 0.0%` en $N=691$ y mejorando el F1 externo en $N_{\text{CC}}=104$ de `0.4789` a **`0.5600` (`ROC-AUC = 0.8380`)**.
4. **Utilidad y riesgos de la cascada adaptativa y clasificación selectiva (Fase V, [`05_CASCADA_ABLACIONES.md`](file:///d:/Proyects/Seguridad_Informacion/05_CASCADA_ABLACIONES.md)):**
   - La cascada `M4` ahorra el **`71.64%` de las inspecciones DOM HTML** ($\bar{m} = 1.79$ etapas por URL) manteniendo `F1 = 0.9248`, `FPR = 0.20%` y la mejor calibración del sistema (`Brier = 0.0309`, `ECE = 0.0209`).
   - Se identificó el mecanismo exacto de su vulnerabilidad: de los `15` falsos negativos no detectados ni abstenidos por `M5` en $N=662$, **`12` (`80.0%`) ocurren por salida temprana benigna en `M0`** ($\bar{p}_{M0} = 0.0106, \mathcal{H} \le 0.15$). Prohibir la salida temprana benigna en `M0` (**`Cascada Conservadora: M1 Obligatorio para Benignos`**) elimina esos 12 errores y eleva el F1 en $N=691$ a **`0.9341`** ahorrando aún el `28.4%` de las evaluaciones DOM. Asimismo, aplicar una política **`M5 Fail-Closed`** sobre las `29` abstenciones (`21` phishing y `8` legítimas) eleva el F1 global en $N=691$ a **`0.9387`** (`Recall = 92.15%`, `FPR = 1.60%`).
5. **Evaluación crítica de los componentes Visual y LLM (Fase VI, [`06_VISUAL_Y_LLM.md`](file:///d:/Proyects/Seguridad_Informacion/06_VISUAL_Y_LLM.md)) y Reproducibilidad (Fase I y VIII, [`01_AUDITORIA_BASELINE.md`](file:///d:/Proyects/Seguridad_Informacion/01_AUDITORIA_BASELINE.md)):**
   - Sobre el subconjunto con capturas reales Chrome CDP ($N = 83$, latencia mediana de captura $2,204.78\text{ ms}$), se demostró que las 32 características visuales estadísticas por sí solas (`Visual_Only_32feat`) tienen **`ROC-AUC = 0.5584`** (indistinguible del azar) y que `27.5%` de los PNG retenidos son lienzos oscuros uniformes en SPAs, explicando por qué `M3_authentic_cdp` (`F1 = 0.8966`) no supera a `M2` (`F1 = 0.9434`, $p = 0.3750$).
   - En el componente LLM (`Groq`), se demostró que `llama-3.1-8b-instant` como clasificador general ($N=30$) está descalibrado (`F1 = 0.0000` en $\tau=0.50$), mientras que `openai/gpt-oss-20b` aplicado selectivamente como desempatador `50/50` sobre las muestras ambiguas abstenidas por `M5` ($N = 9$ llamadas en vivo con ambas clases) eleva el F1 de `0.6667` a **`0.8333`** (`0` FP, `2` FN) con un costo amortizado de **`$0.0186 USD` por `1,000` URLs**.

---

## 2. Tabla Maestra Consolidada de Resultados Verificados

| Sistema / Modelo | Cohorte Evaluada | $N$ Total ($N_{\text{phish}} / N_{\text{legit}}$) | Cobertura | Accuracy | Precision | Recall | F1-Score (IC 95% Bootstrap) | FPR | ROC-AUC | PR-AUC | Brier | ECE |
|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|
| **`M0` (Autoridad URL, 11 vars)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9291` | `0.9080` | `0.8272` | `0.8658 [0.8265, 0.9012]` | `0.0320` | `0.9522` | `0.9261` | `0.0604` | `0.0662` |
| **`M1` (URL + Infra, 34 vars)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9580` | `0.9880` | `0.8586` | `0.9188 [0.8861, 0.9480]` | `0.0040` | `0.9760` | `0.9617` | `0.0405` | `0.0568` |
| **`M2` (URL + Infra + DOM, 50 vars)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9638` | `0.9884` | `0.8796` | **`0.9315 [0.9024, 0.9568]`** | `0.0040` | `0.9735` | `0.9652` | `0.0397` | `0.0680` |
| **`M3_global` (+ Visual, 82 vars)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9638` | `0.9940` | `0.8743` | `0.9308 [0.9000, 0.9565]` | `0.0020` | `0.9746` | `0.9655` | `0.0372` | `0.0609` |
| **`M4` (Cascada Calibrada 3 etapas)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9609` | `0.9940` | `0.8639` | **`0.9248 [0.8946, 0.9514]`** | **`0.0020`** | `0.9786` | `0.9685` | **`0.0309`** | **`0.0209`** |
| **`Cascada Conservadora (M1 oblig.)`** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9653` | `0.9884` | `0.8848` | **`0.9341 [0.9052, 0.9595]`** | `0.0040` | `0.9852` | `0.9756` | `0.0252` | `0.0177` |
| **`M5_selective` (Solo Decididas)** | Interna Decidida | `662 (170 / 492)` | `95.8%` | `0.9773` | `1.0000` | `0.9118` | **`0.9538 [0.9288, 0.9748]`** | **`0.0000`** | `0.9793` | `0.9721` | `0.0226` | `0.0149` |
| **`M5_FailClosed` (Retención Cautelar)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9653` | `0.9565` | `0.9215` | **`0.9387 [0.9111, 0.9612]`** | `0.0160` | `0.9786` | `0.9685` | `0.0309` | `0.0209` |
| **`Config A` (`HybridM0`, `POST /check`)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9407` | `1.0000` | `0.7853` | `0.8798 [0.8393, 0.9140]` | **`0.0000`** | `0.9904` | `0.9803` | `0.0442` | `0.1558` |
| **`Config C` (`HybridM0 -> M1 -> M2/M5`)** | Interna `host_unseen` | `691 (191 / 500)` | `100.0%` | `0.9580` | `1.0000` | `0.8482` | **`0.9178 [0.8842, 0.9471]`** | **`0.0000`** | `0.9912` | `0.9822` | `0.0315` | `0.0890` |
| **`M2` en Cohorte CDP Auténtica** | Interna CDP Real | `83 (28 / 55)` | `100.0%` | `0.9639` | `1.0000` | `0.8929` | **`0.9434 [0.8627, 1.0000]`** | `0.0000` | `0.9929` | `0.9876` | `0.0363` | `0.0358` |
| **`M3_authentic_cdp` (Entrenado CDP)** | Interna CDP Real | `83 (28 / 55)` | `100.0%` | `0.9277` | `0.8667` | `0.9286` | `0.8966 [0.8000, 0.9688]` | `0.0727` | `0.9789` | `0.9623` | `0.0517` | `0.0902` |
| **`Visual_Only_32feat` (Señal Visual)** | Interna CDP Real | `83 (28 / 55)` | `100.0%` | `0.3373` | `0.3373` | `1.0000` | `0.5045 [0.3725, 0.6167]` | `1.0000` | **`0.5584`** | `0.4436` | `0.2189` | `0.0851` |
| **`M0_full` Crudo Externo** | Externa Disjunta | `1,054 (600 / 454)` | `100.0%` | `0.4782` | `0.5527` | `0.4367` | `0.4879 [0.4494, 0.5256]` | `0.4670` | `0.4859` | `0.5594` | `0.4166` | `0.4210` |
| **`M0_full` `strip_www()` Externo** | Externa Disjunta | `1,054 (600 / 454)` | `100.0%` | `0.6262` | `0.8503` | `0.4167` | **`0.5593 [0.5198, 0.5976]`** | **`0.0969`** | **`0.7530`** | **`0.8135`** | `0.2628` | `0.2541` |
| **`HybridM0` Sin Tranco ($\tau=0.35$)** | Externa Disjunta | `1,054 (600 / 454)` | `100.0%` | `0.6499` | `0.9117` | `0.4300` | **`0.5844 [0.5457, 0.6209]`** | `0.0551` | **`0.7710`** | **`0.8181`** | `0.2073` | `0.2289` |
| **`HybridM0` Con Tranco ($\tau=0.50$)** | Externa Disjunta | `1,054 (600 / 454)` | `100.0%` | `0.6176` | `0.9713` | `0.3383` | `0.5019 [0.4586, 0.5440]` | **`0.0132`** | **`0.8077`** | **`0.8712`** | `0.1932` | `0.2185` |
| **`M2_CC` `strip_www()` Externo Vivo** | Externa Viva CC | `104 (54 / 50)` | `43.3%` | `0.7212` | `0.9630` | `0.4815` | **`0.6420 [0.5128, 0.7500]`** | **`0.0200`** | **`0.9248`** | **`0.9423`** | `0.2521` | `0.2480` |
| **`Config C` Crudo Externo Vivo** | Externa Viva CC | `104 (54 / 50)` | `43.3%` | `0.6827` | `1.0000` | `0.3889` | **`0.5600 [0.4242, 0.6829]`** | **`0.0000`** | **`0.8380`** | **`0.8819`** | `0.2115` | `0.1980` |

---

## 3. Índice de Entregables y Artefactos Verificables

### Informes Científicos por Fase (en la raíz del repositorio):
- **Fase I:** [`01_AUDITORIA_BASELINE.md`](file:///d:/Proyects/Seguridad_Informacion/01_AUDITORIA_BASELINE.md) y [`01_auditoria_baseline_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase1_auditoria/01_auditoria_baseline_results.json)
- **Fase II:** [`02_VALIDACION_EXTERNA.md`](file:///d:/Proyects/Seguridad_Informacion/02_VALIDACION_EXTERNA.md), [`external_validation_dataset_n1200.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_validation_dataset_n1200.csv), [`external_predictions_n1200.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_predictions_n1200.csv), [`02_validacion_externa_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/02_validacion_externa_results.json) y [`02b_external_forensic_www_ablation.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/02b_external_forensic_www_ablation.json)
- **Fase III:** [`03_EXTENSION_REAL.md`](file:///d:/Proyects/Seguridad_Informacion/03_EXTENSION_REAL.md), [`03_extension_real_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase3_extension/03_extension_real_results.json) y [`03_per_request_extension_and_cascade_log.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase3_extension/03_per_request_extension_and_cascade_log.csv)
- **Fase IV:** [`04_COMPARACION_CIENTIFICA.md`](file:///d:/Proyects/Seguridad_Informacion/04_COMPARACION_CIENTIFICA.md) y [`04_comparacion_cientifica_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase4_comparacion/04_comparacion_cientifica_results.json)
- **Fase V:** [`05_CASCADA_ABLACIONES.md`](file:///d:/Proyects/Seguridad_Informacion/05_CASCADA_ABLACIONES.md), [`05_cascada_ablaciones_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase5_cascada/05_cascada_ablaciones_results.json) y [`05_pareto_and_policies_table.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase5_cascada/05_pareto_and_policies_table.csv)
- **Fase VI:** [`06_VISUAL_Y_LLM.md`](file:///d:/Proyects/Seguridad_Informacion/06_VISUAL_Y_LLM.md) y [`06_visual_y_llm_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase6_visual_llm/06_visual_y_llm_results.json)
- **Fase VII:** [`07_ANALISIS_ESTADISTICO.md`](file:///d:/Proyects/Seguridad_Informacion/07_ANALISIS_ESTADISTICO.md), [`07_analisis_estadistico_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase7_estadistica/07_analisis_estadistico_results.json) y [`07_all_hypothesis_tests_table.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv)

### Entregables Finales Consolidados (Fase IX y X):
- **A.** [`INFORME_FINAL_VALIDACION_PHISHPE_SCOPUS.md`](file:///d:/Proyects/Seguridad_Informacion/INFORME_FINAL_VALIDACION_PHISHPE_SCOPUS.md)
- **B.** [`MATRIZ_TRAZABILIDAD_FINAL.csv`](file:///d:/Proyects/Seguridad_Informacion/MATRIZ_TRAZABILIDAD_FINAL.csv)
- **C.** [`RESUMEN_PARA_REDACTOR_CIENTIFICO.md`](file:///d:/Proyects/Seguridad_Informacion/RESUMEN_PARA_REDACTOR_CIENTIFICO.md)
- **D.** [`LIMITACIONES_Y_PENDIENTES.md`](file:///d:/Proyects/Seguridad_Informacion/LIMITACIONES_Y_PENDIENTES.md)
- **E.** [`VALIDACION_AUTOMATICA.json`](file:///d:/Proyects/Seguridad_Informacion/VALIDACION_AUTOMATICA.json)
- **F.** [`evidencia_phishpe_validacion_final.zip`](file:///d:/Proyects/Seguridad_Informacion/evidencia_phishpe_validacion_final.zip)

---

## 4. Comandos de Reproducción Exacta desde Cero

Para regenerar todos los análisis, tablas, figuras y la doble auditoría automática sobre la rama `experimental/validacion-scopus-fase2`:

```powershell
python scripts/fase2_01_auditoria_baseline.py
python scripts/fase2_02_build_and_evaluate_external.py
python scripts/fase2_02b_external_forensic_analysis.py
python scripts/fase2_03_extension_real.py
python scripts/fase2_04_comparacion_baselines.py
python scripts/fase2_05_cascada_ablaciones.py
python scripts/fase2_06_visual_y_llm.py
python scripts/fase2_07_analisis_estadistico.py
python scripts/reproduce_all_validation_tables_and_figures.py
python scripts/fase2_09_package_and_double_audit.py
```
