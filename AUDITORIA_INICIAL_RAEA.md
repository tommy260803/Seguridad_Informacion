# AUDITORÍA INICIAL Y FORENSE DE RAEA-PHISH
**Fecha:** 22 de Octubre de 2026  
**Rama:** `research/risk-aware-policy`  
**Equipo Auditor:** Comité Científico Multidisciplinar (Investigador Principal ML Ciberseguridad, Ingeniero Senior FastAPI/Inferencia, Científico de Datos en Clasificación Selectiva, Diseñador Experimental y Auditor de Reproducibilidad QA)  
**Objetivo:** Análisis forense exhaustivo del estado real del método RAEA-Phish (*Automated Detection of Phishing Websites Through Risk- and Availability-Aware Adaptive Evidence Acquisition*), identificación de causa raíz de las anomalías P1–P10, y definición del plan de reconciliación metodológica.

---

## 1. RESUMEN EJECUTIVO DE HALLAZGOS FORENSES

Tras una inspección minuciosa del código fuente (`phishguard_orchestrator/raea/`), los scripts de evaluación (`scripts/run_raea_*.py`), y los artefactos generados en `artifacts/raea/`, se han determinado de forma fehaciente las causas raíz de las discrepancias observadas:

1. **Causa Raíz de P1 y P2 (Discrepancia entre Matriz de Confusión y Riesgo Ponderado):**
   - En `scripts/run_raea_comparative_experiments.py` (línea 267), las predicciones de RAEA fueron mapeadas binariamente como:
     ```python
     pred_raea = 1 if raea_res.decision == "phishing" else 0
     ```
   - Cuando RAEA emitía `decision = "uncertain"` (abstención), la predicción binaria forzada asignaba automáticamente el valor `0` (*legítimo* / *fail-open*).
   - La matriz de confusión reportada en `baseline_comparison.csv` (`TP=125, FP=20, FN=25, TN=130`, suma = 300) fue calculada sobre este vector forzado con todas las 300 muestras.
   - De las 60 abstenciones reales, **40 correspondían a sitios legítimos** y **20 a sitios de phishing**.
   - Al forzar la abstención a `0`, las 40 legítimas se sumaron a $TN$ ($90 + 40 = 130$) y las 20 de phishing se sumaron a $FN$ ($5 + 20 = 25$). Por pura coincidencia aritmética del umbral de M1 ($0.50$), la matriz forzada de RAEA resultó numéricamente idéntica a la de M1 ($125, 20, 130, 25$).
   - Por el contrario, la función `compute_weighted_risk` evaluó el vector de abstenciones explícitas (`abstained_list`), cobrando una penalización por abstención $C_{\text{abst}} = 0.35$ a esas 60 muestras en lugar del coste de error de clasificación ($\gamma = 15.0$ para FN o $C_{\text{FP}} = 1.0$ para FP).
   - Por tanto, el riesgo de RAEA ($0.3867$) reflejó la clasificación selectiva ($5 \text{ FN} \times 15 + 20 \text{ FP} \times 1 + 60 \text{ Abst} \times 0.35 = 116.0 / 300 = 0.3867$), mientras que la matriz de confusión reportada reflejó una política de despliegue forzado *Fail-Open* ($25 \text{ FN} \times 15 + 20 \text{ FP} \times 1 = 395.0 / 300 = 1.3167$).

2. **Causa Raíz de P3 (Modalidades y F1 vs M1):**
   - RAEA consultó en promedio 2.0233 modalidades frente a las 2.0000 fijas de M1.
   - En cobertura forzada al 100% (*Fail-Open*), RAEA obtiene exactamente el mismo F1 que M1 ($0.8475$).
   - La ventaja científica de RAEA **no** radica en superar a M1 en precisión simétrica sobre la población completa forzada, sino en su capacidad de clasificación selectiva (reducción de falsos negativos de 25 a 5 en la población decidida, alcanzando $F1 = 0.9091$ con cobertura del 80%) y en mitigar los falsos negativos prematuros observados en la cascada heurística por entropía (B3).

3. **Causa Raíz de P4 (Identidad entre Ablación A5 y A6):**
   - La variante A5 desactiva la guarda de salida benigna en $M_0$ (`enforce_benign_guard=False`).
   - Sin embargo, bajo la matriz de coste asimétrico ($\gamma = 15.0, C_{\text{FP}} = 1.0$) y coste de abstención $C_{\text{abst}} = 0.35$, la condición Bayes-óptima para declarar un sitio como benigno en la etapa 0 requiere que el riesgo de error de clasificación benigna ($15.0 \cdot p_0$) sea menor o igual que la mejor alternativa inmediata ($C_{\text{abst}} = 0.35$). Esto impone implícitamente $p_0 \le 0.35 / 15.0 \approx 0.0233$.
   - El umbral explícito de la guarda benigna es $p_{\text{safe}} = 0.0200$.
   - En la partición de prueba ($N=300$), solo 4 muestras tuvieron probabilidades en el intervalo $(0.0200, 0.0233]$, y en las cuatro, el valor esperado de adquirir información de red ($\mathcal{Q}_{\text{network}}$) fue inferior al riesgo terminal, provocando la adquisición de red en ambas variantes.
   - En consecuencia, la política Bayesiana minimizadora de riesgo ya incorpora de forma natural la aversión a la salida benigna prematura, haciendo que la guarda explícita actúe como un mecanismo redundante de defensa en profundidad.

4. **Causa Raíz de P5 (Heurística en VOI vs Estimación Empírica):**
   - En `risk.py`, la reducción esperada de riesgo posterior se aproximó mediante factores deterministas fijos ($25\%$ de riesgo residual para red, $20\%$ para HTML).
   - Se debe auditar y reportar abiertamente este diseño como una aproximación analítica de orden cero, complementándola con el cálculo empírico de reducción de riesgo Bayesiano observado en la cohorte de entrenamiento ($N=300$).

5. **Causa Raíz de P6 y P7 (Inconsistencias Narrativas y Pruebas Estadísticas):**
   - Las pruebas de McNemar corregidas por Holm-Bonferroni indican que la precisión binaria simétrica de RAEA no es estadísticamente superior a M1 ($p = 1.000$) ni a M2 ($p = 1.000$).
   - La superioridad estadística de RAEA existe únicamente cuando se evalúa la función de pérdida asimétrica y coste operacional ($p < 0.001$), lo cual debe documentarse con total rigor metodológico sin inducir a interpretaciones erróneas.

6. **Causa Raíz de P8, P9 y P10 (Independencia de Partición, Datos Empíricos y Trazabilidad):**
   - La partición de evaluación ($N=300$, `test_eval`) se mantuvo estrictamente desacoplada del entrenamiento del estimador de disponibilidad (`train_avail`, $N=300$).
   - Las latencias y disponibilidades no fueron simuladas sintéticamente, sino extraídas de los sondeos empíricos reales de Cohorte 2 (`probe_predictions.csv`).
   - Se requiere un archivo CSV granular con las 300 predicciones individuales y sus variantes de despliegue forzado para garantizar reproducibilidad total.

---

## 2. MAPA FORENSE DE DEFECTOS Y ACCIONES DE MITIGACIÓN

| ID | Hallazgo Forense | Archivo Origen | Artefacto Afectado | Corrección Metodológica |
|---|---|---|---|---|
| **P1/P2** | Coerción oculta de abstenciones a benigno (`Fail-Open`), generando matriz de confusión de 300 muestras incompatible con el 20% de abstención reportado. | `scripts/run_raea_comparative_experiments.py:267` | `baseline_comparison.csv` | Desacoplar formalmente la evaluación en dos regímenes: **Selectivo** ($N_{\text{decided}}=240$) y **Despliegues Forzados** (*Fail-Open*, *Fail-Closed*, *Threshold-0.5*). |
| **P3** | RAEA consulta 2.0233 modalidades frente a 2.000 de M1 sin ganar F1 en cobertura 100%. | `artifacts/raea/baseline_comparison.csv` | `raea_results.csv` | Declarar con transparencia que la ventaja de RAEA reside en la reducción de falsos negativos críticos bajo clasificación selectiva, no en F1 bruto a cobertura total. |
| **P4** | Resultados de ablación A5 (sin guarda) idénticos a A6 (completo). | `scripts/run_raea_ablation_study.py` | `ablation_results.csv` | Instrumentar el registro granular de activación de guardas (`guard_activation_log.csv`) y fundamentar matemáticamente la redundancia analítica con $\gamma=15$. |
| **P5** | Factores de reducción de riesgo VOI fijados heurísticamente (0.25, 0.20). | `phishguard_orchestrator/raea/risk.py:63` | `cost_estimation_results.csv` | Redactar `VALUE_OF_INFORMATION_AUDIT.md` y computar la reducción empírica de pérdida Bayesiana en `train_avail`. |
| **P6** | Discrepancias entre métricas narrativas de M0 y tablas CSV. | Informes narrativos previos | Tablas de M0 | Reconciliar las tablas con la verdad única de `probe_predictions.csv`. |
| **P7** | Ausencia de significancia estadística en McNemar tras ajuste Holm-Bonferroni ($p > 0.05$). | `scripts/run_raea_statistical_analysis.py` | `statistical_tests.csv` | Declarar explícitamente la no superioridad en exactitud binaria simétrica y restringir la significancia estadística a la pérdida ponderada asimétrica. |
| **P8** | Verificación de fuga de datos en el conjunto de test ($N=300$). | `artifacts/raea/raea_partitions.csv` | Conjunto de datos de prueba | Documentar la estricta partición temporal e independencia de estimadores. |
| **P9** | Origen de mediciones de latencia y disponibilidad. | `artifacts/corrections_phase2/eval/probe_predictions.csv` | `operational_latency.csv` | Demostrar el origen empírico de los sondeos de red y HTTP. |
| **P10** | Ausencia de exportación individual de predicciones para auditoría fila por fila. | Scripts de prueba | Registro de predicciones | Generar `selective_predictions.csv` con trazabilidad completa de cada una de las 300 instancias. |
