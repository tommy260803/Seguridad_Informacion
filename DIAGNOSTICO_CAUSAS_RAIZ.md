# Diagnóstico de Causas Raíz y Matriz de Trazabilidad: RAEA-Phish

## 1. Identificación y Análisis de Causas Raíz

### Problema P1: Fuga Metodológica en Calibración y Sensibilidad de M0
* **Archivo:** `research/sensitivity_m0.py`
* **Función:** `run_m0_sensitivity()`
* **Problema:** El calibrador isotónico (`CalibratedClassifierCV`) se ajusta sobre la partición `(X_val, y_val)` y posteriormente se evalúa sobre ese mismo conjunto `X_val` para calcular el Brier score y el F1-Score reportado ($0.9024$).
* **Causa Raíz:** Ausencia de un split tripartito estricto en desarrollo. Se utilizó la totalidad del conjunto de validación tanto para el ajuste del regresor isotónico no-paramétrico como para la estimación del rendimiento predictivo del modelo calibrado. Al ser la regresión isotónica un estimador monótono por tramos que minimiza el error cuadrático sobre sus datos de entrenamiento, evaluarlo en la misma muestra subestima drásticamente el error de calibración y sobrestima la generalización.
* **Evidencia:** Líneas 94-98 de `research/sensitivity_m0.py`:
  ```python
  cal = CalibratedClassifierCV(estimator=FrozenEstimator(base), method="isotonic")
  cal.fit(X_val, y_val)
  probs = cal.predict_proba(X_val)[:, 1]
  ```
* **Corrección:** 
  1. Estructurar una separación formal tripartita de datos dentro del entorno de desarrollo:
     - $D_{\text{train}}$: Subconjuntos de entrenamiento para el clasificador base ($N \in \{30,835; 61,670; 92,505; 123,341\}$).
     - $D_{\text{cal}}$: Partición dedicada exclusivamente al ajuste del calibrador isotónico ($N = 13,215$).
     - $D_{\text{val\_eval}}$: Partición de evaluación y selección independiente fuera de muestra ($N = 13,215$), con partición por dominios disjuntos para evitar contaminación cruzada.
  2. Preservar la partición de prueba canónica ($D_{\text{test}}$, $N=26,430$) completamente congelada y ajena al proceso de selección.
* **Prueba de Aceptación:** Prueba automática `test_c1_m0_training_calibration_split_disjoint` que verifique que el conjunto de índices utilizado para `cal.fit()` y para `cal.predict_proba()` tiene intersección vacía ($D_{\text{cal}} \cap D_{\text{val\_eval}} = \emptyset$) y cero solapamiento de dominios.

---

### Problema P2: Igualación Retrospectiva de Cobertura mediante Selección Top-k en Test
* **Archivo:** `research/evaluate.py`
* **Función:** `run_evaluation()`
* **Problema:** Para comparar RAEA y Chow B5 a "cobertura equivalente", el evaluador ordenaba las probabilidades de confianza de la cohorte de prueba completa y seleccionaba las $k$ observaciones más confiables mediante `np.argsort(conf)[-k:]`.
* **Causa Raíz:** Forzar retrospectivamente la cobertura exacta en el conjunto de prueba utilizando información global de la distribución de confianza de la cohorte evaluada. Esto no constituye una política prospectiva desplegable, sino un artificio descriptivo *post-hoc*.
* **Evidencia:** Líneas 682 y 703 de `research/evaluate.py`:
  ```python
  idx_b5 = np.argsort(conf1_c)[-k:]
  ...
  idx_r = np.argsort(conf_raea_c)[-k:]
  ```
* **Corrección:**
  1. Diseñar la regla de cobertura sobre datos de desarrollo / validación (`UMBRALES_DESARROLLO.csv`):
     - Para un objetivo de cobertura $c^*$, calcular sobre la partición de validación el umbral de confianza congelado $\theta_{\text{cov}}$ tal que $\mathbb{P}_{\text{val}}(\text{conf}(x) \ge \theta_{\text{cov}}) = c^*$.
     - Serializar los umbrales $\theta_{\text{cov}}$ antes de tocar las cohortes de evaluación.
  2. En la evaluación de prueba (retrospectiva y externa), aplicar el umbral congelado a cada observación individual de forma prospectiva e independiente:
     $$d(x) = \begin{cases}
     \arg\max_y p(y \mid x), & \text{si } \max_y p(y \mid x) \ge \theta_{\text{cov}} \\
     \text{abstain}, & \text{en caso contrario}
     \end{cases}$$
  3. Registrar la cobertura real empírica obtenida sin forzar el tamaño del conjunto decidido.
  4. Mantener el barrido `np.argsort` exclusivamente como análisis descriptivo complementario en `CURVAS_RETROSPECTIVAS.csv`.
* **Prueba de Aceptación:** Prueba automática `test_c6_prospective_frozen_thresholds_no_argsort` que verifique que las decisiones de políticas congeladas no utilizan `argsort` ni dependen del tamaño $N$ de la cohorte de prueba.

---

### Problema P3: Falta de Ventaja Incremental del Estimador de Disponibilidad frente a Prior Constante A2
* **Archivo:** `src/phishguard_orchestrator/raea/policy.py`, `availability.py` y `research/evaluate.py`
* **Función:** `AvailabilityEstimator.predict_availability()`, `ActionSelector.select_action()`
* **Problema:** En la cohorte externa independiente ($N=240$), la variante con disponibilidad empírica constante (Ablación A2, $\bar{\pi}_{\text{net}}=0.683, \bar{\pi}_{\text{html}}=0.427$) supera a RAEA completo en coste normalizado ($0.2825$ frente a $0.5071$) y riesgo penalizado ($0.5946$ frente a $0.7196$).
* **Causa Raíz:**
  1. **Degradación por Domain Shift:** El clasificador logístico de disponibilidad entrenado sobre características léxicas en la sonda retrospectiva colapsa a $\text{ROC-AUC} \approx 0.5212$ en la cohorte externa. Las heurísticas de URL no generalizan temporalmente para predecir si un servidor web remoto responderá meses después.
  2. **Sobreestimación de Éxito en Enlaces Inactivos:** El estimador predictivo asigna probabilidades de disponibilidad infladas a sitios web que en realidad están caídos. Esto induce a RAEA a solicitar adquisiciones de red y HTML que fallan en la práctica, pagando el coste de penalización de fallo ($0.20$ y $0.30$) sin adquirir características y terminando en abstención.
  3. **Frugalidad Óptima del Prior Fijo (A2):** La tasa base histórica $\bar{\pi}_{\text{html}} = 0.427$ es suficientemente baja y conservadora como para desincentivar consultas a $M_2$ salvo en casos de altísima incertidumbre, evitando el derroche de coste en adquisiciones destinadas al fracaso.
* **Corrección:**
  1. No alterar los costes ni los umbrales para forzar artificialmente que RAEA gane a A2 en la cohorte externa.
  2. Documentar el hallazgo negativo de forma rigurosa: el estimador de disponibilidad basado en características léxicas no es robusto frente al desfase temporal.
  3. Generar la tabla de `CASOS_DIVERGENTES.csv` trazando muestra por muestra qué decisiones cambiaron entre RAEA y A2 y por qué A2 ahorra coste.
  4. Redefinir la contribución científica: el modelado de disponibilidad es indispensable frente a la ignorancia completa de la literatura (A1 sin disponibilidad tiene coste explosivo de $0.7792$), pero un prior base empírico constante (A2) proporciona una cota de robustez operacional superior a estimadores predictivos sobreajustados.
* **Prueba de Aceptación:** Prueba automática `test_c4_a2_divergent_cases_traceability` que verifique que cada caso divergente entre RAEA y A2 tiene su coste, riesgo y disponibilidad documentados y que se reporta honestamente la ventaja de A2.

---

## 2. Matriz de Trazabilidad de Datos, Modelos y Experimentos

| Etapa | Componente | Dataset Origen | Población ($N$) | Rol Experimental |
|---|---|---|:---:|---|
| **M0 Base** | Clasificador Léxico | `samples.csv` (train) | 123,341 | Entrenamiento de representaciones de URL |
| **M0 Cal** | Calibrador Isotónico | `samples.csv` (val_cal) | 13,215 | Ajuste de probabilidades bien calibradas |
| **M0 Eval** | Selección de Hiperparámetros | `samples.csv` (val_eval) | 13,215 | Evaluación independiente fuera de muestra para sensibilidad |
| **M0 Test** | Test Reservado | `samples.csv` (test) | 26,430 | Conjunto congelado intacto (cero desarrollo) |
| **M1 Infra** | Modelo de Red | `m1-real` | 1,200 | Clasificador de infraestructura DNS/BGP |
| **M2 DOM** | Modelo de Contenido | `m2-real` | 800 | Clasificador de características DOM/HTML |
| **Avail Est** | Estimador Disponibilidad | `probe_raw.jsonl` (train_avail) | 300 | Entrenamiento de $\hat{\pi}_m(x_0)$ |
| **Avail Val** | Test Disponibilidad In-Sample | `probe_raw.jsonl` (test_eval) | 300 | Medición de ROC-AUC in-sample (0.74 / 0.81) |
| **Eval Retro** | Cohorte Retrospectiva | `probe_raw.jsonl` (completas) | 118 | Evaluación exploratoria histórica de RAEA |
| **Eval Ext** | Cohorte Prospectiva Externa | `external_multimodal_probe_n240.jsonl` | 240 | Evaluación independiente prospectiva de políticas congeladas |
