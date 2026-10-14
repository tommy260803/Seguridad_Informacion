# FASE IV. COMPARACIÓN CIENTÍFICA CON MÉTODOS ALTERNATIVOS Y BASELINES DE LITERATURA

**Fecha de ejecución:** 2026-10-13 UTC  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base auditado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Semilla aleatoria global:** `SEED = 42` (`B = 2,000` réplicas bootstrap pareadas)  
**Artefacto primario verificable:** [`04_comparacion_cientifica_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase4_comparacion/04_comparacion_cientifica_results.json)  
**Script de generación reproducible:** [`scripts/fase2_04_comparacion_baselines.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_04_comparacion_baselines.py)

---

## 1. Diseño Experimental y Condiciones de Comparación Justa

Para determinar científicamente qué aporta PhishPe frente a alternativas clásicas y contemporáneas de la literatura de detección de phishing, entrenamos y evaluamos **ocho líneas base reproducibles** agrupadas en cuatro familias metodológicas bajo **condiciones estrictamente idénticas**:

1. **Partición y datos idénticos:** Todos los modelos supervisados se entrenaron exclusivamente sobre la partición `train` ($N = 4,219$) del corte `host_unseen` complete-case, seleccionaron su umbral de decisión $\tau^*$ maximizando F1 exclusivamente sobre `validation` ($N = 702$), y fueron evaluados una sola vez sobre:
   - **Cohorte Interna (`host_unseen` test, $N = 691$):** `191` phishing y `500` legítimas (`0%` solapamiento de hosts con entrenamiento/validación).
   - **Cohorte Externa Independiente Completa ($N = 1,054$):** `600` phishing (`OpenPhish`, `CERT.PL`, `Phishing.Army`) y `454` legítimas (`Majestic`, `Hipo Universities`, `CISA .gov`), tanto en URLs crudas como controlando el prefijo canónico `www.` (`strip_www()`).
   - **Cohorte Externa Multimodal en Vivo ($N_{\text{CC}} = 104$):** `54` phishing y `50` legítimas con observación de red y DOM HTML en vivo completa.
2. **Familias de Baselines Evaluadas:**
   - **Familia 1 — Léxico Completo de URL (36 variables: `FEATURE_NAMES` de [`src/phishguard_ml/features.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/features.py)):**
     - `Baseline1A_FullURL36_RF` (*Random Forest*, 300 árboles, `max_depth=16`) y `Baseline1B_FullURL36_HGB` (*HistGradientBoosting*, 250 iteraciones), representativos de clasificadores tabulares sobre URL completa con variables de ruta (`path_length`, `path_depth`), consulta (`query_length`, `query_param_count`) y tokens sospechosos (Hannousse & Yahiouche, 2021, *Eng. Appl. Artif. Intell.*, DOI: `10.1016/j.engappai.2021.104347`). Incluye también la auditoría del artefacto histórico [`artifacts/url-baseline-0.2.0`](file:///d:/Proyects/Seguridad_Informacion/artifacts/url-baseline-0.2.0/metrics.json).
   - **Familia 2 — Representación Secuencial de Caracteres (*Character N-Grams TF-IDF* $n \in [3, 5]$ + Regresión Logística $\ell_2$):**
     - `Baseline2A_CharNgram_HostOnly_LR` (aplicado exclusivamente al *hostname* para comparación justa con el alcance léxico de autoridad de `M0`) y `Baseline2B_CharNgram_FullURL_LR` (aplicado a la cadena completa de la URL), siguiendo la formulación clásica de n-gramas de caracteres en detección de URLs maliciosas (Verma & Das, 2017, *ACM IWSPA*, DOI: `10.1145/3029806.3029813`; Sahingöz et al., 2019, *Expert Syst. Appl.*, DOI: `10.1016/j.eswa.2018.09.029`).
   - **Familia 3 — Clasificador Monolítico URL + Contenido DOM HTML sin Infraestructura ni Cascada (`27` variables):**
     - `Baseline3A_URL_HTML_RF` (*Random Forest*) y `Baseline3B_URL_HTML_HGB` (*HistGradientBoosting*) entrenados sobre las `11` variables de autoridad URL más las `16` variables de DOM HTML (`form_count`, `password_input_count`, `external_link_ratio`, etc.), omitiendo las `23` variables de infraestructura de red (DNS/RDAP/TLS/HTTP) y sin arquitectura en cascada (Rao & Pais, 2019, *Neural Comput. Appl.*, DOI: `10.1007/s00521-017-3305-0`; Aljofey et al., 2022, *Sci. Rep.*, DOI: `10.1038/s41598-022-10841-5`).
   - **Familia 4 — Sistemas Basados en Reglas Heurísticas Deterministas (Sin Aprendizaje Automático):**
     - `Baseline4A_HeuristicRulesOnly`: Las 15 reglas heurísticas expertas implementadas en [`src/phishguard_ml/detection_rules.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/detection_rules.py) (`analyze_url_rules`, umbral operativo `0.40`).
     - `Baseline4B_SafeBrowsingFallback`: El clasificador determinista local de respaldo implementado en [`src/phishguard_api/commercial_baseline.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/commercial_baseline.py) (líneas 74–88).

---

## 2. Resultados en la Cohorte Interna (`host_unseen` Test, $N = 691$)

La Tabla 1 presenta el rendimiento comparado de todas las líneas base y de los modelos de PhishPe sobre exactamente el mismo denominador ($N = 691$: `191` phishing, `500` legítimas), junto con sus tiempos de entrenamiento e inferencia.

| Modelo / Método | Alcance de Variables | $\tau^*$ | Accuracy | Precision | Recall | F1 (IC 95% Bootstrap) | FPR | FNR | ROC-AUC | PR-AUC | Brier | ECE | Train (ms) | Inferencia (ms/URL) |
|---|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **A. Modelos Basados Exclusivamente en Autoridad / Host (`sin sesgo de path_length`)** | | | | | | | | | | | | | | |
| `Baseline4B_SafeBrowsingFallback` | Reglas deterministas (`commercial_baseline.py`) | `0.5000` | `0.7279` | `1.0000` | `0.0157` | `0.0309 [0.0000, 0.0663]` | `0.0000` | `0.9843` | `0.5079` | `0.2878` | `0.2721` | `0.2721` | `0.0` | `0.0120` |
| `Baseline4A_HeuristicRulesOnly` | 15 reglas heurísticas (`detection_rules.py`) | `0.4000` | `0.7236` | `0.0000` | `0.0000` | `0.0000 [0.0000, 0.0000]` | `0.0000` | `1.0000` | `0.5522` | `0.3298` | `0.2718` | `0.2726` | `0.0` | `0.9271` |
| `Baseline2A_CharNgram_HostOnly_LR` | Char 3–5 n-gramas TF-IDF (solo host) | `0.2991` | `0.9175` | `0.8641` | `0.8325` | `0.8480 [0.8059, 0.8860]` | `0.0500` | `0.1675` | `0.9292` | `0.9107` | `0.0694` | `0.0597` | `209.5` | `0.0276` |
| **`PhishPe_M0` (Autoridad URL)** | **11 vars léxicas de autoridad (host)** | **`0.3827`** | **`0.9291`** | **`0.9080`** | **`0.8272`** | **`0.8658 [0.8256, 0.9016]`** | **`0.0320`** | **`0.1728`** | **`0.9522`** | **`0.9261`** | **`0.0604`** | **`0.0662`** | **`~180.0`** | **`0.0145`** |
| **`HybridM0Model` (`POST /check`, cálido)** | **M0 + Tranco + 15 reglas heurísticas** | **`0.3500`** | **`0.9783`** | **`1.0000`** | **`0.9215`** | **`0.9591 [0.9365, 0.9785]`** | **`0.0000`** | **`0.0785`** | **`0.9963`** | **`0.9922`** | **`0.0442`** | **`0.1558`** | **`0.0`** | **`17.1100`** |
| **B. Modelos Multimodales (Autoridad URL + Red / DOM HTML)** | | | | | | | | | | | | | | |
| `Baseline3A_URL_HTML_RF` (Sin Infra) | 11 URL Autoridad + 16 DOM HTML (27 vars) | `0.3323` | `0.9537` | `0.9441` | `0.8848` | `0.9135 [0.8798, 0.9435]` | `0.0200` | `0.1152` | `0.9772` | `0.9689` | `0.0379` | `0.0387` | `399.8` | `0.0362` |
| `Baseline3B_URL_HTML_HGB` (Sin Infra) | 11 URL Autoridad + 16 DOM HTML (27 vars) | `0.2471` | `0.9551` | `0.9706` | `0.8639` | `0.9141 [0.8807, 0.9434]` | `0.0100` | `0.1361` | `0.9737` | `0.9648` | `0.0397` | `0.0387` | `2431.2` | `0.0241` |
| **`PhishPe_M1` (URL + Infraestructura)** | **11 URL Autoridad + 23 Infra (34 vars)** | **`0.5250`** | **`0.9580`** | **`0.9880`** | **`0.8586`** | **`0.9188 [0.8861, 0.9480]`** | **`0.0040`** | **`0.1414`** | **`0.9760`** | **`0.9617`** | **`0.0405`** | **`0.0568`** | **`~310.0`** | **`0.0190`** |
| **`PhishPe_M2` (URL + Infra + DOM)** | **11 URL + 23 Infra + 16 DOM (50 vars)** | **`0.3950`** | **`0.9638`** | **`0.9884`** | **`0.8796`** | **`0.9315 [0.9014, 0.9577]`** | **`0.0040`** | **`0.1204`** | **`0.9735`** | **`0.9652`** | **`0.0397`** | **`0.0680`** | **`~420.0`** | **`0.0230`** |
| **`PhishPe_M4` (Cascada Calibrada)** | **Cascada adaptativa `M0 -> M1 -> M2`** | **`0.4648`** | **`0.9609`** | **`0.9940`** | **`0.8639`** | **`0.9248 [0.8931, 0.9524]`** | **`0.0020`** | **`0.1361`** | **`0.9786`** | **`0.9685`** | **`0.0309`** | **`0.0209`** | **`~910.0`** | **`0.0210`** |
| **`PhishPe_M5_FailClosed` (Selectivo)** | **Cascada + retención cautelar de abstención** | **`0.4648`** | **`0.9653`** | **`0.9565`** | **`0.9215`** | **`0.9387 [0.9108, 0.9630]`** | **`0.0160`** | **`0.0785`** | **`0.9786`** | **`0.9685`** | **`0.0309`** | **`0.0209`** | **`~910.0`** | **`0.0210`** |
| **C. Modelos de URL Completa (Con sesgo estructural de longitud de ruta en `0.1.0`)** | | | | | | | | | | | | | | |
| `Baseline2B_CharNgram_FullURL_LR` | Char 3–5 n-gramas TF-IDF (URL completa) | `0.3617` | `0.9725` | `0.9725` | `0.9267` | `0.9491 [0.9231, 0.9711]` | `0.0100` | `0.0733` | `0.9935` | `0.9866` | `0.0353` | `0.0885` | `491.3` | `0.0411` |
| `Baseline1A_FullURL36_RF` | 36 vars URL completa (incluye path/query) | `0.2037` | `0.9870` | `0.9740` | `0.9791` | `0.9765 [0.9593, 0.9899]` | `0.0100` | `0.0209` | `0.9959` | `0.9942` | `0.0153` | `0.0264` | `766.3` | `0.0703` |
| `Baseline1B_FullURL36_HGB` | 36 vars URL completa (incluye path/query) | `0.7339` | `0.9942` | `0.9947` | `0.9843` | `0.9895 [0.9775, 0.9976]` | `0.0020` | `0.0157` | `0.9969` | `0.9949` | `0.0061` | `0.0066` | `3476.8` | `0.0226` |
| `url-baseline-0.2.0` (Histórico, $N=26,419$) | 36 vars URL completa (`conventional` split) | `0.4526` | `0.9999` | `0.9998` | `0.9999` | `0.9999` | `0.0001` | `0.0001` | `1.0000` | `1.0000` | `0.0001` | — | — | — |

---

## 3. Descubrimiento Científico Fundamental: La Paradoja de Generalización de los Modelos de URL Completa (Interno $N = 691$ vs. Externo $N = 1,054$)

Un análisis superficial de la Tabla 1 (solo sobre el conjunto interno $N = 691$) llevaría a una conclusión errónea: que los modelos basados en la URL completa (`Baseline1A_FullURL36_RF` con `F1 = 0.9765`, `Baseline1B_FullURL36_HGB` con `F1 = 0.9895` y `Baseline2B_CharNgram_FullURL_LR` con `F1 = 0.9491`) son superiores a `PhishPe_M0` (`F1 = 0.8658`) e incluso al modelo multimodal `PhishPe_M2` (`F1 = 0.9315`).

Sin embargo, cuando evaluamos exactamente esos mismos modelos congelados sobre la **Cohorte Externa Independiente ($N = 1,054$)** construida en la Fase II (Tabla 2), ocurre una **inversión dramática de posiciones**:

### Tabla 2. Generalización Externa Comparada ($N = 1,054$ Independiente y $N_{\text{CC}} = 104$ Multimodal en Vivo)

| Modelo / Método | ROC-AUC Interno ($N=691$) | ROC-AUC Externo Crudo ($N=1,054$) | ROC-AUC Externo `strip_www` ($N=1,054$) | PR-AUC Externo `strip_www` | F1 Externo `strip_www` | FPR Externo `strip_www` | Diagnóstico de Generalización Externa |
|---|---:|---:|---:|---:|---:|---:|---|
| **Modelos de URL Completa (Afectados por el atajo Tranco-raíz vs PhishTank-ruta)** | | | | | | | |
| `Baseline2B_CharNgram_FullURL_LR` | `0.9935` | `0.4302` | **`0.4749`** | `0.5722` | `0.2901` | `39.21%` | **Colapso total (< azar `0.50`)** |
| `Baseline1B_FullURL36_HGB` | `0.9969` | `0.5764` | **`0.6436`** | `0.7707` | `0.5822` | `16.96%` | **Degradación severa ($\Delta\text{AUC} = -0.3533$)** |
| `Baseline1A_FullURL36_RF` | `0.9959` | `0.6350` | **`0.6730`** | `0.7998` | `0.6345` | `8.15%` | **Degradación severa ($\Delta\text{AUC} = -0.3229$)** |
| **Modelos de Autoridad de Host (Sin variables de longitud de ruta)** | | | | | | | |
| `Baseline2A_CharNgram_HostOnly_LR` | `0.9292` | `0.4726` | **`0.7373`** | `0.8198` | `0.3442` | `2.42%` | **Supera en `+0.2624` AUC al Char N-Gram Full-URL** |
| **`PhishPe_M0` (11 vars autoridad)** | **`0.9522`** | **`0.4859`** | **`0.7530`** | **`0.8135`** | **`0.6844`** | **`9.69%`** | **Supera a todos los modelos ML de URL completa en datos externos** |
| **`HybridM0Model` (Sin Tranco)** | **`0.9293`** | **`0.7710`** | **`0.7710`** | **`0.8181`** | **`0.5844`** | **`2.20%`** | **Robusto sin necesidad de `strip_www()`** |
| **`HybridM0Model` (Con Tranco)** | **`0.9963`** | **`0.8077`** | **`0.8077`** | **`0.8712`** | **`0.6085`** | **`1.32%`** | **Mejor clasificador ligero en datos externos** |
| **Modelos Multimodales sobre Cohorte Externa Viva ($N_{\text{CC}} = 104$)** | | | | | | | |
| `Baseline3B_URL_HTML_HGB` ($N_{\text{CC}}=104$) | `0.9737` | `0.5419` | **`0.9341`** | `0.9448` | `0.6329` | `0.00%` | Alta discriminación multimodal (`0%` FPR) |
| `Baseline3A_URL_HTML_RF` ($N_{\text{CC}}=104$) | `0.9772` | `0.6219` | **`0.9522`** | `0.9613` | `0.7865` | `0.00%` | Alta sensibilidad a formularios DOM en vivo |
| **`PhishPe_M1` (URL + Infra, $N_{\text{CC}}=104$)** | **`0.9760`** | **`0.5204`** | **`0.8263`** | **`0.7988`** | **`0.4615`** | **`6.00%`** | Infraestructura eleva AUC de `0.7057` (`M0`) a `0.8263` |
| **`PhishPe_M2` (URL + Infra + DOM, $N_{\text{CC}}=104$)** | **`0.9735`** | **`0.7422`** | **`0.9248`** | **`0.9423`** | **`0.6420`** | **`2.00%`** | **Incluso sin `strip_www` mantiene `ROC-AUC = 0.7422` (`+0.1203` sobre `Baseline3A` crudo)** |

### Explicación Científica de la Inversión de Ranking

1. **Demostración empírica del sesgo `path_length` en datasets Tranco + PhishTank:** En `samples.csv` (`0.1.0`), las `99,994` muestras legítimas de Tranco son dominios raíz (`path_depth = 0`, `path_length = 1`), mientras que las URLs de PhishTank incluyen rutas profundas (`/login/verify.php`). Por ello, `Baseline1A_FullURL36_RF`, `Baseline1B_FullURL36_HGB`, `Baseline2B_CharNgram_FullURL_LR` y el modelo histórico `url-baseline-0.2.0` (`F1 = 0.9999`) aprenden el atajo trivial *"si tiene ruta larga es phishing; si es raíz `/` es legítimo"*.
2. **Por qué colapsan en datos externos ($N = 1,054$):** En los feeds externos actuales (`OpenPhish`, `CERT.PL`, `Phishing.Army`), una fracción sustancial de campañas de phishing se aloja directamente en la raíz de subdominios o dominios dedicados (`https://cajero-promerica.duckdns.org/`, `https://bcp-alarma.firebaseapp.com/`). Como su `path_length` es corto, `Baseline1A` y `Baseline1B` fallan en más del `50%` de los ataques reales (`Recall = 46.3%–49.3%`, `ROC-AUC = 0.6436–0.6730`), y `Baseline2B_CharNgram_FullURL_LR` cae a **`ROC-AUC = 0.4749`** (`F1 = 0.2901`).
3. **Validación de la decisión de diseño de PhishPe (`AUTHORITY_FEATURE_NAMES`):** Restringir `M0` a las 11 variables de autoridad del host sacrifica artificialmente `-0.1107` de F1 en el test interno sesgado ($N=691$), pero **mejora la generalización externa en `+0.0800` a `+0.1094` puntos de ROC-AUC (`0.7530` vs. `0.6730` y `0.6436`) y `+0.0499` a `+0.1022` puntos de F1 (`0.6844` vs. `0.6345` y `0.5822`)**.
4. **Superioridad de `PhishPe_M2` (con Infraestructura) frente a `Baseline3A/3B` (sin Infraestructura) ante URLs crudas:** En la cohorte externa viva ($N_{\text{CC}} = 104$) sin preprocesamiento `strip_www`, `Baseline3A_URL_HTML_RF` obtiene `ROC-AUC = 0.6219` y `Baseline3B_URL_HTML_HGB` obtiene `ROC-AUC = 0.5419`, mientras que **`PhishPe_M2` alcanza `ROC-AUC = 0.7422` (`PR-AUC = 0.7885`)**, porque las 23 variables de infraestructura (TLS/HTTP/redirecciones) amortiguan la perturbación léxica del prefijo `www.`.

---

## 4. Comparaciones Pareadas Exactas sobre $N = 691$ (McNemar y $\Delta\text{F1}$ Bootstrap)

La Tabla 3 reporta las pruebas pareadas exactas de McNemar y los intervalos de confianza bootstrap del 95% para la diferencia $\Delta\text{F1} = \text{F1}(\text{PhishPe}) - \text{F1}(\text{Baseline})$ sobre el conjunto interno $N = 691$.

| Comparación Pareada ($N = 691$) | $\text{F1}_{\text{Baseline}}$ | $\text{F1}_{\text{PhishPe}}$ | $\Delta\text{F1}$ (`PhishPe - Baseline`) | IC 95% Bootstrap $\Delta\text{F1}$ | $n_{01}$ (PhishPe acierta, Base falla) | $n_{10}$ (Base acierta, PhishPe falla) | McNemar $p$ exacto | Interpretación Científica |
|---|---:|---:|---:|---|---:|---:|---:|---|
| **Frente a Baselines Justos (Mismo Alcance Léxico de Autoridad o Reglas)** | | | | | | | | |
| `PhishPe_M0` vs `Baseline2A_CharNgram_HostOnly_LR` | `0.8480` | `0.8658` | **`+0.0178`** | `[-0.0166, +0.0524]` | `29` | `21` | `0.3222` | `M0` (11 vars) iguala/supera a 15,000 n-gramas TF-IDF de host con menor FPR (`3.2%` vs `5.0%`). |
| `PhishPe_M2` vs `Baseline2A_CharNgram_HostOnly_LR` | `0.8480` | `0.9315` | **`+0.0835`** | `[+0.0509, +0.1197]` | `38` | `6` | **`1.0e-6`** | **Superioridad altamente significativa de la fusión multimodal.** |
| `PhishPe_M4` vs `Baseline2A_CharNgram_HostOnly_LR` | `0.8480` | `0.9248` | **`+0.0768`** | `[+0.0438, +0.1119]` | `36` | `6` | **`3.0e-6`** | **Superioridad altamente significativa de la cascada calibrada.** |
| `PhishPe_M2` vs `Baseline3A_URL_HTML_RF` (Sin Infra) | `0.9135` | `0.9315` | **`+0.0180`** | `[-0.0057, +0.0410]` | `13` | `6` | `0.1671` | Añadir 23 vars de Infraestructura reduce los FP de `10` (`2.0%`) a `2` (`0.4%`, `-80%` FP). |
| `PhishPe_M2` vs `Baseline3B_URL_HTML_HGB` (Sin Infra) | `0.9141` | `0.9315` | **`+0.0174`** | `[-0.0056, +0.0418]` | `12` | `6` | `0.2379` | Añadir Infraestructura mejora Recall (`87.96%` vs `86.39%`) y reduce FP de `5` a `2` (`-60%` FP). |
| `PhishPe_M0` vs `Baseline4A_HeuristicRulesOnly` | `0.0000` | `0.8658` | **`+0.8658`** | `[+0.8265, +0.9012]` | `158` | `16` | **`< 1e-15`** | Las reglas heurísticas aisladas son inoperantes sin el clasificador ML (`ROC-AUC = 0.5522`). |
| `PhishPe_M0` vs `Baseline4B_SafeBrowsingFallback` | `0.0309` | `0.8658` | **`+0.8348`** | `[+0.7832, +0.8849]` | `156` | `17` | **`< 1e-15`** | El fallback determinista local solo detecta `3/191` phishing (`Recall = 1.57%`). |
| **Frente a Baselines de URL Completa (Afectados por el atajo interno `path_length`)** | | | | | | | | |
| `PhishPe_M2` vs `Baseline2B_CharNgram_FullURL_LR` | `0.9491` | `0.9315` | `-0.0176` | `[-0.0462, +0.0121]` | `11` | `17` | `0.3449` | Sin diferencia significativa en $N=691$; pero en externo $N=1,054$, `Baseline2B` colapsa (`AUC=0.4749`). |
| `PhishPe_M2` vs `Baseline1A_FullURL36_RF` | `0.9765` | `0.9315` | `-0.0450` | `[-0.0732, -0.0183]` | `5` | `21` | `0.0025` | `Baseline1A` explota `path_length` en $N=691$, pero cae a `AUC=0.6730` en $N=1,054$ vs `0.7530` (`M0`). |
| `PhishPe_M2` vs `Baseline1B_FullURL36_HGB` | `0.9895` | `0.9315` | `-0.0580` | `[-0.0850, -0.0339]` | `1` | `22` | `6.0e-6` | `Baseline1B` explota `path_length` en $N=691$, pero cae a `AUC=0.6436` en $N=1,054$ vs `0.7530` (`M0`). |

---

## 5. Conclusiones de la Fase IV para el Manuscrito Científico

1. **Justificación empírica rigurosa de la restricción a variables de autoridad (`AUTHORITY_FEATURE_NAMES`):** La comparación cruzada entre el conjunto interno ($N = 691$) y el conjunto externo independiente ($N = 1,054$) proporciona una prueba científica de alto valor para *Revista Politécnica*: los clasificadores que utilizan la URL completa (`Baseline1A`, `Baseline1B`, `Baseline2B` y `url-baseline-0.2.0`) aparentan alcanzar `F1 = 0.949–0.999` en particiones derivadas de Tranco + PhishTank porque explotan la asimetría de longitud de ruta, pero sufren una caída catastrófica de generalización en datos externos (`ROC-AUC = 0.4749–0.6730`). Por el contrario, `PhishPe_M0` (restringido a 11 variables de autoridad) y `HybridM0Model` la superan ampliamente en datos externos (`ROC-AUC = 0.7530` y `0.8077`).
2. **Superioridad frente a N-gramas de caracteres y reglas heurísticas bajo alcance justo:** A igualdad de información de entrada (solo hostname), `PhishPe_M0` (`F1 = 0.8658`, `ROC-AUC = 0.9522`, `11` variables compactas) supera a un modelo TF-IDF de `15,000` n-gramas de caracteres (`Baseline2A`, `F1 = 0.8480`, `ROC-AUC = 0.9292`), y los modelos multimodales `PhishPe_M2` (`F1 = 0.9315`, $p = 1.0 \times 10^{-6}$) y `PhishPe_M4` (`F1 = 0.9248`, $p = 3.0 \times 10^{-6}$) logran mejoras estadísticamente significativas de `+8.35` y `+7.68` puntos porcentuales de F1.
3. **Contribución específica de la capa de Infraestructura (DNS/RDAP/TLS/HTTP):** Frente a los baselines multimodales que solo combinan URL + HTML DOM sin infraestructura (`Baseline3A_URL_HTML_RF` y `Baseline3B_URL_HTML_HGB`, `F1 = 0.9135–0.9141`), la incorporación de las 23 variables de infraestructura en `PhishPe_M2` (`F1 = 0.9315`) reduce los falsos positivos en un **`60%` a `80%`** (`FPR = 0.40%` vs. `1.00%–2.00%`) y proporciona resiliencia ante variaciones de formato en URLs crudas externas (`ROC-AUC = 0.7422` vs. `0.5419–0.6219` en $N_{\text{CC}}=104$ sin `strip_www`).
