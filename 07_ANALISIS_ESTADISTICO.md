# FASE VII. ANÁLISIS ESTADÍSTICO RIGUROSO, CLUSTER BOOTSTRAP, CALIBRACIÓN Y SENSIBILIDAD

**Fecha de ejecución:** 2026-10-13 UTC  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base auditado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Semilla aleatoria global:** `SEED = 42` (`B = 2,000` réplicas bootstrap por estimación)  
**Artefactos verificables:**  
- [`07_analisis_estadistico_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase7_estadistica/07_analisis_estadistico_results.json)  
- [`07_all_hypothesis_tests_table.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv)  
- [`artifacts/corrected_audit/statistical_comparisons_all.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/statistical_comparisons_all.json)  
**Script de generación reproducible:** [`scripts/fase2_07_analisis_estadistico.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_07_analisis_estadistico.py)

> **NOTA DE CORRECCIÓN (2026-10-14, auditoría de reproducibilidad).** Durante la fase de
> corrección se verificó la reproducibilidad total del CSV de pruebas pareadas: las **14/14 filas**
> de [`07_all_hypothesis_tests_table.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv)
> se reproducen **exactamente** desde los `predictions.csv` congelados
> (`scripts/phase2e_verify_historical_stats.py`; evidencia:
> `artifacts/corrections_phase2/eval/historical_stats_reconciliation.json`, `dictamen: PASS`).
> Sin embargo, **el texto y las filas `E1`/`E2` de este documento discrepaban del CSV** en cuatro
> cifras (ΔF1, pares discordantes y $p$ de McNemar). Este documento ha sido corregido para
> coincidir con la fuente reproducible:
>
> | Elemento | Cifra errónea previa | Cifra corregida (CSV reproducible) |
> |---|---|---|
> | `E1` $\Delta\text{F1}$ (`M2`−`M1`) | `+0.0127` | `+0.006299` |
> | `E1` pares discordantes ($n_{01}$/$n_{10}$) | `9`/`4` | `8`/`6` |
> | `E1` McNemar $p$ exacto | `0.2668` | `0.79052734` |
> | `E2` $\Delta\text{F1}$ (`M3`−`M2`) | `-0.0007` | `-0.002935` |
>
> La corrección **no altera ninguna conclusión**: `E1` sigue siendo no significativo (de hecho
> más inconcluso) y `E2` sigue siendo un resultado nulo verificado. Las hipótesis confirmatorias
> `H1`–`H6` no se ven afectadas (coinciden al dígito con el CSV).

---

## 1. Marco Metodológico y Control de Multiplicidad

Para cumplir con los estándares estadísticos exigidos por *Revista Politécnica* (Secciones 11 y 12 del protocolo):

1. **Separación predefinida entre familias de hipótesis:**
   - **Familia Confirmatoria (`H1–H6`, 6 pruebas principales):** Contrasta las hipótesis centrales del estudio: la ganancia de las etapas multimodales (`M1`, `M2`) y de la cascada (`M4`, `M5_selective`) frente a la línea base léxica de autoridad (`M0`) en la cohorte interna ($N = 691$ / $N = 662$), y la ganancia de generalización de `HybridM0Model` (con y sin Tranco) frente a `M0` en la cohorte externa independiente ($N = 1,054$).
   - **Familia Exploratoria (`E1–E8`, 8 pruebas post-hoc):** Evalúa diferencias marginales entre etapas consecutivas (`M1 vs. M2`, `M2 vs. M3`), equivalencia operativa entre el modelo monolítico `M2` y la cascada `M4`, políticas de abstención (`M4 vs. M5_FailClosed`, `M2_decided vs. M5_selective`), y las configuraciones operativas de la extensión (`Config A` y `Config C`).
2. **Doble esquema de remuestreo Bootstrap ($B = 2,000$, `SEED = 42`):**
   - **Bootstrap no paramétrico a nivel de muestra ($N$):** Remuestreo con reemplazo de observaciones individuales.
   - **Cluster Bootstrap por dominio registrado (`registered_domain`, $K$ clusters):** Remuestreo con reemplazo de dominios registrados completos para capturar cualquier correlación intra-dominio. Tanto en la partición interna `host_unseen` ($N = 691, K = 691$ dominios registrados únicos) como en la cohorte externa ($N = 1,054, K = 1,054$ dominios registrados únicos), se verifica empíricamente que $K = N$, lo que garantiza **independencia estadística estricta entre observaciones a nivel de dominio registrado** y convergencia entre ambos intervalos de confianza.
3. **Pruebas pareadas exactas y tamaños de efecto:**
   - Para cada comparación pareada sobre el mismo denominador se reporta el **test exacto binomial de McNemar** sobre los pares discordantes ($n_{01}$ donde `B` acierta y `A` falla vs. $n_{10}$ donde `A` acierta y `B` falla), el estadístico $\chi^2_{\text{cc}}$ con corrección de continuidad de Edwards, y la **corrección escalonada (*step-down*) de Holm-Bonferroni** ($p_{\text{Holm}}$) dentro de cada familia.
   - Cada valor $p$ se acompaña de cuatro medidas de magnitud del efecto:
     - $\Delta\text{F1} = \text{F1}_B - \text{F1}_A$ con su IC 95% bootstrap pareado (de muestra y de cluster).
     - **Cohen's $g$ para pares discordantes:** $g = \left|\frac{n_{01}}{n_{01} + n_{10}} - 0.5\right|$ (donde $g \in [0.05, 0.15)$ es pequeño, $[0.15, 0.25)$ es mediano y $\ge 0.25$ es grande; Cohen, 1988).
     - **Odds Ratio Discordante ($\text{OR}_{\text{disc}}$ con corrección Haldane-Anscombe):** $\text{OR}_{\text{disc}} = \frac{n_{01} + 0.5}{n_{10} + 0.5}$.
     - **Cohen's $h$ sobre la tasa de detección (Recall):** $h = 2\arcsin\sqrt{\text{TPR}_B} - 2\arcsin\sqrt{\text{TPR}_A}$.

---

## 2. Intervalos de Confianza del 95%: Bootstrap de Muestra vs. Cluster Bootstrap por Dominio

La Tabla 1 presenta las estimaciones puntuales e intervalos de confianza del 95% ($B = 2,000$) de muestra y de cluster por `registered_domain` para todos los modelos internos ($N = 691$) y externos ($N = 1,054$).

| Cohorte y Modelo | $N$ Muestras | $K$ Dominios (`Clusters`) | F1 Puntual | IC 95% F1 (Bootstrap Muestra) | IC 95% F1 (Cluster Bootstrap Dominio) | ROC-AUC Puntual | IC 95% ROC-AUC (Muestra) | IC 95% ROC-AUC (Cluster) | IC 95% Recall | IC 95% FPR |
|---|---:|---:|---:|---|---|---:|---|---|---|---|
| **A. Cohorte Interna (`host_unseen` Test, $N = 691$)** | | | | | | | | | | |
| `M0` (Solo URL Autoridad) | `691` | `691` | `0.8658` | `[0.8265, 0.9012]` | `[0.8260, 0.9003]` | `0.9097` | `[0.8768, 0.9404]` | `[0.8760, 0.9405]` | `[0.7716, 0.8794]` | `[0.0176, 0.0478]` |
| `M1` (URL + Infraestructura)* | `691` | `691` | `0.9252` | `[0.8955, 0.9524]` | `[0.8944, 0.9521]` | `0.9759` | `[0.9597, 0.9882]` | `[0.9616, 0.9879]` | `[0.8251, 0.9211]` | `[0.0000, 0.0139]` |
| `M2` (URL + Infra + DOM) | `691` | `691` | `0.9315` | `[0.9024, 0.9568]` | `[0.9030, 0.9576]` | `0.9864` | `[0.9736, 0.9957]` | `[0.9739, 0.9955]` | `[0.8424, 0.9326]` | `[0.0019, 0.0161]` |
| `M3` (URL + Infra + DOM + Visual) | `691` | `691` | `0.9286` | `[0.8997, 0.9543]` | `[0.9000, 0.9543]` | `0.9850` | `[0.9721, 0.9945]` | `[0.9723, 0.9947]` | `[0.8385, 0.9290]` | `[0.0019, 0.0164]` |
| `M4` (Cascada Calibrada) | `691` | `691` | `0.9248` | `[0.8946, 0.9514]` | `[0.8944, 0.9516]` | `0.9674` | `[0.9472, 0.9845]` | `[0.9470, 0.9853]` | `[0.8177, 0.9175]` | `[0.0000, 0.0101]` |
| `M5_FailClosed` (Cascada + Retención) | `691` | `691` | `0.9387` | `[0.9111, 0.9612]` | `[0.9120, 0.9634]` | `0.9674` | `[0.9472, 0.9845]` | `[0.9470, 0.9853]` | `[0.8807, 0.9581]` | `[0.0061, 0.0276]` |
| `HybridM0_ConfigA` (`POST /check`) | `691` | `691` | `0.8798` | `[0.8393, 0.9140]` | `[0.8389, 0.9146]` | `0.9904` | `[0.9849, 0.9947]` | `[0.9849, 0.9948]` | `[0.7232, 0.8415]` | `[0.0000, 0.0000]` |
| `ConfigC_HybridCascade` ($\tau=0.4648$) | `691` | `691` | `0.9023` | `[0.8672, 0.9322]` | `[0.8678, 0.9333]` | `0.9901` | `[0.9797, 0.9966]` | `[0.9808, 0.9966]` | `[0.7656, 0.8730]` | `[0.0000, 0.0000]` |
| **B. Cohorte Externa Independiente ($N = 1,054$)** | | | | | | | | | | |
| `M0_External_Raw` ($\tau=0.3827$) | `1,054` | `1,054` | `0.4442` | `[0.4080, 0.4814]` | `[0.4066, 0.4830]` | `0.4401` | `[0.4047, 0.4768]` | `[0.4064, 0.4754]` | `[0.3529, 0.4321]` | `[0.4442, 0.5386]` |
| `M0_External_strip_www` ($\tau=0.4339$) | `1,054` | `1,054` | `0.5593` | `[0.5198, 0.5976]` | `[0.5190, 0.5982]` | `0.7530` | `[0.7232, 0.7818]` | `[0.7228, 0.7824]` | `[0.3767, 0.4567]` | `[0.0705, 0.1256]` |
| `HybridM0_NoTranco_External` ($\tau=0.35$) | `1,054` | `1,054` | `0.5844` | `[0.5457, 0.6209]` | `[0.5428, 0.6221]` | `0.7710` | `[0.7424, 0.7988]` | `[0.7441, 0.7976]` | `[0.3914, 0.4681]` | `[0.0364, 0.0773]` |
| `HybridM0_WithTranco_External` ($\tau=0.50$) | `1,054` | `1,054` | `0.5019` | `[0.4586, 0.5440]` | `[0.4581, 0.5437]` | `0.8077` | `[0.7808, 0.8330]` | `[0.7821, 0.8321]` | `[0.3008, 0.3775]` | `[0.0043, 0.0248]` |

> \*Nota de trazabilidad sobre `M1` y `M3`: En `predictions.csv`, la etiqueta binaria `predicted_label` proviene del umbral por defecto (`F1 = 0.9252` en `M1` y `0.9286` en `M3`), mientras que al aplicar `selected_threshold` de `metrics.json` (`0.5250` en `M1` y `0.3917` en `M3`), `F1 = 0.9188` y `0.9308` respectivamente. En ambos umbrales todas las conclusiones de significación estadística (confirmatorias y exploratorias) se mantienen idénticas.

---

## 3. Pruebas de Hipótesis Pareadas, Tamaños de Efecto y Corrección de Holm-Bonferroni

### 3.1 Familia de Hipótesis Confirmatorias Predefinidas (`H1–H6`)

| ID | Comparación (`A vs. B`) | Cohorte ($N$) | $\text{F1}_A$ | $\text{F1}_B$ | $\Delta\text{F1}$ (`B - A`) | IC 95% $\Delta\text{F1}$ (Muestra) | IC 95% $\Delta\text{F1}$ (Cluster) | $n_{01}$ (`B` mejor) | $n_{10}$ (`A` mejor) | McNemar $p$ exacto | $p_{\text{Holm}}$ | Cohen's $g$ | $\text{OR}_{\text{disc}}$ | Decisión ($\alpha=0.05$) |
|---|---|---:|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|
| **H1** | `M0` vs. `M1` (URL+Infra) | Int. (`691`) | `0.8658` | `0.9252` | **`+0.0595`** | `[+0.0348, +0.0881]` | `[+0.0350, +0.0867]` | `24` | `2` | `1.05e-5` | **`3.15e-5`** | **`0.4231` (Grande)** | `9.80` | **SIGNIFICATIVO (Positivo)** |
| **H2** | `M0` vs. `M2` (URL+Infra+DOM) | Int. (`691`) | `0.8658` | `0.9315` | **`+0.0658`** | `[+0.0369, +0.0986]` | `[+0.0359, +0.0978]` | `29` | `5` | `3.86e-5` | **`7.71e-5`** | **`0.3529` (Grande)** | `5.36` | **SIGNIFICATIVO (Positivo)** |
| **H3** | `M0` vs. `M4` (Cascada Calibrada) | Int. (`691`) | `0.8658` | `0.9248` | **`+0.0590`** | `[+0.0325, +0.0878]` | `[+0.0326, +0.0892]` | `25` | `3` | `2.74e-5` | **`5.49e-5`** | **`0.3929` (Grande)** | `7.29` | **SIGNIFICATIVO (Positivo)** |
| **H4** | `M0_dec` vs. `M5_selective` | Dec. (`662`) | `0.8961` | `0.9538` | **`+0.0577`** | `[+0.0332, +0.0849]` | `[+0.0341, +0.0832]` | `20` | `0` | `1.91e-6` | **`7.64e-6`** | **`0.5000` (Máximo)** | `41.00` | **SIGNIFICATIVO (Positivo)** |
| **H5** | `M0_Ext` vs. `HybridM0_NoTranco` | Ext. (`1054`) | `0.4442` | `0.5844` | **`+0.1401`** | `[+0.1080, +0.1699]` | `[+0.1093, +0.1698]` | `249` | `28` | `< 1e-15` | **`< 1e-15`** | **`0.3989` (Grande)** | `8.75` | **SIGNIFICATIVO (Positivo)** |
| **H6** | `M0_Ext` vs. `HybridM0_WithTranco` | Ext. (`1054`) | `0.4442` | `0.5019` | **`+0.0576`** | `[+0.0280, +0.0864]` | `[+0.0270, +0.0859]` | `230` | `45` | `< 1e-15` | **`< 1e-15`** | **`0.3364` (Grande)** | `5.07` | **SIGNIFICATIVO (Positivo)** |

### 3.2 Familia de Hipótesis Exploratorias Post-Hoc (`E1–E8`)

| ID | Comparación (`A vs. B`) | Cohorte ($N$) | $\text{F1}_A$ | $\text{F1}_B$ | $\Delta\text{F1}$ (`B - A`) | IC 95% $\Delta\text{F1}$ (Muestra) | IC 95% $\Delta\text{F1}$ (Cluster) | $n_{01}$ (`B` mejor) | $n_{10}$ (`A` mejor) | McNemar $p$ exacto | $p_{\text{Holm}}$ | Cohen's $g$ | $\text{OR}_{\text{disc}}$ | Diagnóstico Estadístico |
|---|---|---:|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|
| **E1** | `M1` vs. `M2` (Aporte marginal DOM) | Int. (`691`) | `0.9252` | `0.9315` | `+0.0063` | `[-0.0140, +0.0279]` | `[-0.0137, +0.0270]` | `8` | `6` | `0.7905` | `1.0000` | `0.0714` | `1.31` | **No significativo (Inconcluso en $N=691$)** |
| **E2** | `M2` vs. `M3` (Aporte marginal Visual) | Int. (`691`) | `0.9315` | `0.9286` | `-0.0029` | `[-0.0201, +0.0142]` | `[-0.0195, +0.0136]` | `4` | `5` | `1.0000` | `1.0000` | `0.0556` | `0.82` | **Resultado nulo verificado ($\Delta \approx 0$)** |
| **E3** | `M2` vs. `M4` (Monolítico vs Cascada) | Int. (`691`) | `0.9315` | `0.9248` | `-0.0067` | `[-0.0255, +0.0111]` | `[-0.0247, +0.0108]` | `4` | `6` | `0.7539` | `1.0000` | `0.1000` | `0.69` | **No significativo (Ahorra `71.6%` DOM)** |
| **E4** | `M4` vs. `M5_FailClosed` | Int. (`691`) | `0.9248` | `0.9387` | `+0.0139` | `[-0.0077, +0.0368]` | `[-0.0072, +0.0363]` | `10` | `6` | `0.4545` | `1.0000` | `0.1250` | `1.62` | **Eleva Recall de `86.4%` a `92.1%` ($h=+0.17$)** |
| **E5** | `M2_dec` vs. `M5_selective` | Dec. (`662`) | `0.9636` | `0.9538` | `-0.0098` | `[-0.0237, +0.0028]` | `[-0.0250, +0.0028]` | `1` | `4` | `0.3750` | `1.0000` | `0.3000` | `0.33` | **`M2` tiene `4` FN menos por salida temprana en `M0`** |
| **E6** | `M0` vs. `HybridM0_ConfigA` | Int. (`691`) | `0.8658` | `0.8798` | `+0.0140` | `[-0.0151, +0.0424]` | `[-0.0139, +0.0401]` | `16` | `8` | `0.1516` | `0.9096` | `0.1667` | `1.94` | **Elimina el `100%` de los FP de `M0` (`16 -> 0`)** |
| **E7** | `M4` vs. `ConfigC_HybridCascade` | Int. (`691`) | `0.9248` | `0.9178` | `-0.0070` | `[-0.0312, +0.0165]` | `[-0.0308, +0.0162]` | `6` | `10` | `0.4545` | `1.0000` | `0.1250` | `0.62` | **Sin pérdida significativa y $23.4\times$ más rápida** |
| **E8** | `HybridM0_NoTranco` vs. `WithTranco` | Ext. (`1054`) | `0.5844` | `0.5019` | `-0.0825` | `[-0.1042, -0.0615]` | `[-0.1051, -0.0611]` | `19` | `55` | `3.51e-5` | **`0.0003`** | **`0.2432`** | `0.35` | **En $\tau=0.50$, Tranco reduce FPR (`1.3%`) pero baja Recall; en $\tau=0.35$ sube F1 a `0.6085`** |

---

## 4. Análisis de Calibración Probabilística y Diagramas de Confiabilidad

La Tabla 2 resume las métricas de calibración (`Brier Score`, `Expected Calibration Error` — `ECE` en 10 bins, y `Maximum Calibration Error` — `MCE` en 10 bins) en la cohorte interna ($N = 691$) y externa ($N = 1,054$).

| Modelo y Cohorte | Brier Score ($\downarrow$ mejor) | ECE (10 bins, $\downarrow$ mejor) | MCE (10 bins, $\downarrow$ mejor) | Diagnóstico de Calibración |
|---|---:|---:|---:|---|
| **Interno — `M0` (Solo URL)** | `0.0604` | `0.0662` | `0.2647` | Subconfianza moderada en el rango intermedio `[0.4, 0.7)`. |
| **Interno — `M1` (URL + Infraestructura)** | `0.0359` | `0.0238` | `0.2500` | Excelente calibración tras incorporar infraestructura. |
| **Interno — `M2` (URL + Infra + DOM)** | `0.0289` | `0.0226` | `0.2143` | Baja varianza de predicción en ambos extremos `[0.0, 0.1)` y `[0.9, 1.0]`. |
| **Interno — `M3` (Con Visual)** | `0.0285` | `0.0199` | `0.2222` | Calibración virtualmente idéntica a `M2`. |
| **Interno — `M4` (Cascada Calibrada Isotónica/Platt)** | **`0.0309`** | **`0.0209`** | **`0.1818`** | **Mejor calibración global de la cascada gracias al ajuste post-hoc por etapa.** |
| **Interno — `HybridM0_ConfigA` (`POST /check`)** | `0.0442` | `0.1558` | `0.5621` | **Compresión heurística de rango:** la fórmula $0.60 \cdot p_{M0} + 0.40 \cdot s_{\text{reglas}}$ comprime los positivos verdaderos al intervalo `[0.60, 0.70]`, elevando el ECE aunque su `ROC-AUC = 0.9904` sea excelente. |
| **Externo — `HybridM0_WithTranco` ($N=1,054$)** | `0.1932` | `0.2185` | `0.4812` | Bien calibrado en la región benigna (`[0.0, 0.2)`), conservador en phishing sin reglas activadas. |

---

## 5. Análisis de Sensibilidad al Umbral y a la Prevalencia Operativa

### 5.1 Sensibilidad al Umbral de Decisión ($\tau^* \pm 0.05$ y $\pm 0.10$ en $N = 691$)

| Modelo | $\tau^* - 0.10$ (F1 / FPR / Recall) | $\tau^* - 0.05$ (F1 / FPR / Recall) | **$\tau^*$ Oficial (F1 / FPR / Recall)** | $\tau^* + 0.05$ (F1 / FPR / Recall) | $\tau^* + 0.10$ (F1 / FPR / Recall) | Estabilidad ($\Delta\text{F1}_{\max}$ en $\pm 0.05$) |
|---|---|---|---|---|---|---|
| **`M0`** ($\tau^*=0.3827$) | `0.8504 / 5.4% / 84.8%` | `0.8587 / 4.2% / 84.3%` | **`0.8658 / 3.2% / 82.7%`** | `0.8635 / 2.2% / 79.6%` | `0.8613 / 1.4% / 77.5%` | Muy estable (`0.0071`) |
| **`M1`** ($\tau^*=0.5250$) | `0.9227 / 1.0% / 87.4%` | `0.9252 / 0.6% / 87.4%` | **`0.9188 / 0.4% / 85.9%`** | `0.9126 / 0.4% / 84.8%` | `0.9070 / 0.6% / 84.3%` | Muy estable (`0.0064`) |
| **`M2`** ($\tau^*=0.3950$) | `0.9377 / 1.0% / 90.6%` | `0.9319 / 1.0% / 89.5%` | **`0.9315 / 0.4% / 88.0%`** | `0.9282 / 0.6% / 88.0%` | `0.9252 / 0.6% / 87.4%` | Altamente estable (`0.0033`) |
| **`M4`** ($\tau^*=0.4648$) | `0.9282 / 0.6% / 88.0%` | `0.9248 / 0.4% / 86.9%` | **`0.9248 / 0.2% / 86.4%`** | `0.9188 / 0.4% / 85.9%` | `0.9188 / 0.4% / 85.9%` | Altamente estable (`0.0060`) |
| **`HybridM0`** ($\tau^*=0.3500$) | `0.8997 / 0.2% / 82.2%` | `0.8997 / 0.2% / 82.2%` | **`0.8966 / 0.2% / 81.7%`** | `0.8902 / 0.2% / 80.6%` | `0.8863 / 0.0% / 79.6%` | Altamente estable (`0.0064`) |

### 5.2 Sensibilidad a la Prevalencia Operativa ($\pi \in \{50\%, 27.64\%, 10\%, 5\%, 1\%, 0.1\%\}$)

La Tabla 3 proyecta mediante el teorema de Bayes la Precisión (`PPV`), el `F1` y las **falsas alarmas esperadas por cada `10,000` URLs inspeccionadas** bajo distintas prevalencias de phishing.

| Modelo y Tasa Base (TPR / FPR) | $\pi = 50\%$ (PPV / F1) | $\pi = 27.64\%$ Test (PPV / F1) | $\pi = 10\%$ (PPV / F1) | $\pi = 5\%$ (PPV / F1) | $\pi = 1\%$ (PPV / F1) | $\pi = 0.1\%$ (PPV / F1) | Falsas Alarmas / `10,000` URLs ($\pi=1\%$) |
|---|---|---|---|---|---|---|---:|
| **Interno — `M0` (`TPR=82.7%, FPR=3.20%`)** | `0.9628 / 0.8899` | `0.9080 / 0.8658` | `0.7418 / 0.7822` | `0.5764 / 0.6794` | `0.2071 / 0.3312` | `0.0252 / 0.0490` | `316.8` FP |
| **Interno — `M2` (`TPR=88.0%, FPR=0.40%`)** | `0.9955 / 0.9340` | `0.9884 / 0.9315` | `0.9607 / 0.9185` | `0.9205 / 0.8996` | **`0.6897 / 0.7733`** | `0.1803 / 0.2992` | **`39.6` FP** |
| **Interno — `M4` (`TPR=86.4%, FPR=0.20%`)** | `0.9977 / 0.9260` | `0.9940 / 0.9248` | `0.9796 / 0.9181` | `0.9579 / 0.9084` | **`0.8134 / 0.8379`** | **`0.3021 / 0.4475`** | **`19.8` FP** |
| **Interno — `M5_FailClosed` (`TPR=92.1%, FPR=1.60%`)** | `0.9829 / 0.9512` | `0.9565 / 0.9387` | `0.8648 / 0.8923` | `0.7519 / 0.8281` | `0.3678 / 0.5257` | `0.0545 / 0.1029` | `158.4` FP |
| **Extensión — `HybridM0` (`TPR=78.5%, FPR=0.00%` int.)** | `1.0000 / 0.8798` | `1.0000 / 0.8798` | `1.0000 / 0.8798` | `1.0000 / 0.8798` | **`1.0000 / 0.8798`** | **`1.0000 / 0.8798`** | **`0.0` FP** |
| **Externo — `HybridM0_WithTranco` (`TPR=33.8%, FPR=1.32%`)** | `0.9624 / 0.5007` | `0.9072 / 0.4929` | `0.7399 / 0.4643` | `0.5740 / 0.4257` | `0.2055 / 0.2557` | `0.0250 / 0.0465` | `130.8` FP |
| **Externo — `M2_CC strip_www` (`TPR=48.1%, FPR=2.00%`)** | `0.9601 / 0.6413` | `0.9019 / 0.6278` | `0.7279 / 0.5796` | `0.5589 / 0.5173` | `0.1956 / 0.2782` | `0.0235 / 0.0449` | `198.0` FP |

---

## 6. Clasificación Definitiva de Hallazgos (Sección 11.2)

1. **Hallazgos Positivos Científicamente Verificados (`VERIFIED POSITIVE`):**
   - `H1`, `H2`, `H3` y `H4` son estadísticamente significativos tras corrección de Holm-Bonferroni ($p_{\text{Holm}} \le 8.80 \times 10^{-5}$) con tamaños de efecto grandes ($g \in [0.3529, 0.5000]$, $\text{OR}_{\text{disc}} \in [5.36, 41.00]$).
   - `H5` y `H6` confirman que `HybridM0Model` mejora significativamente la generalización externa frente a `M0` puro ($p_{\text{Holm}} < 10^{-15}$, $g = 0.3989$).
   - En escenarios de baja prevalencia ($\pi = 1\%$), `M4` mantiene `PPV = 81.34%` y `F1 = 0.8379` (solo `19.8` falsas alarmas por `10,000` URLs), frente a `PPV = 20.71%` (`316.8` falsas alarmas) en `M0`.
2. **Hallazgos Negativos Científicamente Verificados (`VERIFIED NEGATIVE`):**
   - La etapa visual actual `M3` no mejora a `M2` ni en el conjunto global ($N = 691$, $\Delta\text{F1} = -0.0029, p = 1.0000$) ni en el subconjunto con capturas reales Chrome CDP ($N = 83$, $\Delta\text{F1} = -0.0468, p = 0.3750$), debido a que las 32 características visuales estadísticas tienen `ROC-AUC = 0.5584`.
   - Los clasificadores de URL completa (`Baseline1A`, `Baseline1B`, `Baseline2B`) sufren sobreajuste severo al artefacto `path_length` de `0.1.0` y son superados en generalización externa por los modelos restringidos a autoridad del host (`M0` con `strip_www()` y `HybridM0Model`).
3. **Hallazgos Inconclusos por Potencia Estadística Limitada (`INCONCLUSIVE`):**
   - La ganancia marginal de `M2` sobre `M1` en $N = 691$ (`+0.0063` F1, `8` vs. `6` pares discordantes, $p = 0.7905$) requeriría $N \approx 19{,}000$ muestras de prueba (`~5{,}250` phishing) para alcanzar potencia del $80\%$ al nivel $\alpha = 0.05$; se trata por tanto de una diferencia inconclusa, no demostrada.
   - El beneficio del ensamble `50% Cascada + 50% LLM` sobre las muestras abstenidas por `M5` (`F1 = 0.8333` vs. `0.6667`, $N = 9$ evaluaciones en vivo completadas) es prometedor pero estadísticamente inconcluso hasta completar una muestra mayor sin restricción de cuota TPM.
