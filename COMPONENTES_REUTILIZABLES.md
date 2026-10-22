# COMPONENTES_REUTILIZABLES.md: Inventario de Interfaces y Componentes Reutilizables

**Proyecto:** RAEA-Phish en PhishPe  
**Directriz:** Cumplir con la restricción obligatoria de NO modificar modelos ni particiones congeladas, reutilizando interfaces limpias y desacopladas.

---

## 1. Módulos y Modelos Reutilizados As-Is (Sin Modificación)

| Componente | Ruta en Repositorio | Descripción / Función Reutilizada | Restricción de Integridad |
| :--- | :--- | :--- | :--- |
| **Modelos Congelados M0–M3** | `artifacts/m0-real/model.joblib`<br>`artifacts/m1-real/model.joblib`<br>`artifacts/m2-real/model.joblib`<br>`artifacts/corrected_audit/m3-authentic-cdp/model.joblib` | Estimadores de probabilidad $P(\text{phishing} \mid x_m)$. Se cargan en modo solo lectura (`joblib.load`). | **Intocables.** Hashes SHA-256 verificados en `MANIFIESTO_MODELOS_SHA256.csv`. |
| **Extractor Léxico de URLs** | `src/phishguard_ml/features.py`<br>`src/phishguard_data/urls.py` | `extract_url_features(context)`, `canonicalize_url(url, psl)`. Proporciona las 11 variables de autoridad y 16 variables URL completas. | Mantener determinismo y normalización `www` (BUG-07). |
| **Extractor de Infraestructura** | `src/phishguard_ml/infrastructure.py`<br>`src/phishguard_infra/` | `extract_infrastructure_features(...)`. Realiza resolución DNS y validación TLS. | Reutilizar tipos y diccionarios de salida. |
| **Extractor de Contenido DOM** | `src/phishguard_ml/content.py`<br>`src/phishguard_content/` | `extract_content_features(...)`. Descarga HTTP y análisis estructural HTML. | Reutilizar límites de tiempo y captura de excepciones. |
| **Extractor Visual CDP** | `src/phishguard_ml/visual.py`<br>`src/phishguard_visual/` | `extract_visual_features(...)`. Captura y perceptual hashing. | Reutilizar interfaz hacia sandbox aislado. |
| **Filtro Bloom Tranco Top-1M** | `src/phishguard_api/bloom_filter.py` | Consulta en memoria de dominios de alta reputación global ($< 0.05\text{ ms}$). | Reutilizar como señal previa en estado $S_0$. |
| **Métricas y Calibración** | `src/phishguard_ml/evaluation.py` | `expected_calibration_error`, `brier_score_loss`, `shannon_entropy`. | Métricas estándar de evaluación. |
| **Esquemas de Base de Datos y API** | `src/phishguard_api/models.py` | Modelos Pydantic y SQLAlchemy (`AnalysisJob`, `AnalysisResult`). | Compatible hacia atrás. |

---

## 2. Componentes Nuevos a Diseñar e Implementar (Módulo RAEA)

Los siguientes componentes conformarán el nuevo submódulo experimental `src/phishguard_orchestrator/raea/`:

1. **`DecisionState` (`state.py`):**
   Estructura inmutable que encapsula:
   - Características observadas hasta la etapa actual ($x_0, x_1, \dots$).
   - Probabilidades de cada modelo disponible ($p_{M0}, p_{M1}, \dots$).
   - Modalidades ya consultadas $\mathcal{M} \subseteq \{\text{url}, \text{infra}, \text{content}, \text{visual}\}$.
   - Historial de estados de adquisición (`success`, `blocked`, `timeout`, `error`).
   - Presupuesto de tiempo y latencia acumulada.

2. **`AvailabilityEstimator` (`availability.py`):**
   Estimador probabilístico calibrado que predice:
   $$P(\text{available}_{\text{infra}} \mid x_0), \quad P(\text{available}_{\text{content}} \mid x_0)$$
   utilizando exclusivamente características disponibles en la etapa inicial $S_0$ (tipo de host IP, acortador, TLD, presencia en Tranco, longitud, homógrafos).

3. **`AcquisitionCostEstimator` (`cost.py`):**
   Estimador del coste y latencia esperada de consultar cada modalidad:
   $$\mathbb{E}[\text{Coste}(m) \mid S_t] = P(\text{avail}_m \mid x_0) \cdot c_m^{\text{succ}} + (1 - P(\text{avail}_m \mid x_0)) \cdot c_m^{\text{fail}}$$

4. **`RiskEstimator` (`risk.py`):**
   Calcula el riesgo de Bayes condicional para las acciones terminales:
   $$\text{Riesgo}(\text{phishing} \mid p) = C_{FP} \cdot (1 - p)$$
   $$\text{Riesgo}(\text{benign} \mid p) = C_{FN} \cdot p$$
   donde $C_{FN} / C_{FP} \ge 1$.

5. **`ActionSelector` & `RiskAvailabilityAwarePolicy` (`policy.py`):**
   Motor de decisión secuencial que implementa la función de selección óptima de acciones:
   $$a^* = \arg\min_{a \in \mathcal{A}(S_t)} \mathcal{Q}(a \mid S_t)$$
   e impone la **Guarda contra Salidas Benignas Prematuras** en la etapa $M0$.

6. **`DecisionLogger` (`logging.py`):**
   Registro estructurado en JSON de cada transición, justificación analítica del valor $\mathcal{Q}(a)$, riesgo estimado y tiempos de ejecución para garantizar auditabilidad total.

---

## 3. Puntos de Acoplamiento y Mecanismo de Activación (Feature Flag)

Para cumplir estrictamente con el principio de no interferencia con el sistema en producción:
- El motor clásico `src/phishguard_orchestrator/engine.py` permanecerá como la política predeterminada (`policy_type="entropy_cascade"`).
- Se incorporará un selector configurable en el orquestador (`policy_type="raea"`) o vía variable de entorno:
  `PHISHGUARD_ORCHESTRATOR_POLICY=raea`
- La API FastAPI en `src/phishguard_api/server.py` y el worker en `worker.py` permitirán activar la política RAEA mediante cabecera HTTP (`X-Policy: raea`), parámetro en el payload del endpoint `/check` y `/analyses`, o flag global, permitiendo pruebas pareadas directas sin perturbar el baseline.
