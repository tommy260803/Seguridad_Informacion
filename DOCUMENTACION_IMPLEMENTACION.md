# DOCUMENTACION_IMPLEMENTACION.md: Documentación de Implementación de RAEA-Phish

**Método:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Paquete Creado:** `src/phishguard_orchestrator/raea/`  
**Pruebas Unitarias:** `tests/test_raea_policy.py` (8 pruebas unitarias e integración, 100% éxito)

---

## 1. Módulos y Clases Implementadas

### 1.1. `models.py`
- **`Action` (Enum):** Define las 6 acciones válidas del POMDP:
  - `STOP_PHISHING`: Parada y veredicto definitivo de phishing.
  - `STOP_BENIGN`: Parada y veredicto definitivo de legítimo (sujeto a la guarda benigna en $M0$).
  - `ACQUIRE_NETWORK`: Adquisición de DNS, IPs y certificados TLS ($m_1$).
  - `ACQUIRE_HTML`: Descarga HTTP y análisis estructural del DOM ($m_2$).
  - `ACQUIRE_VISUAL`: Renderizado headless en sandbox Playwright CDP ($m_3$).
  - `ABSTAIN`: Parada preventiva con veredicto de incertidumbre.
- **`DecisionState` (dataclass inmutable):** Almacena el vector léxico $x_0$, modalidades consultadas, estados de adquisición ($\mathbf{s}_t$), probabilidad calibrada actual, presupuesto restante y la señal booleana de riesgo léxico.
- **`RAEAConfig`:** Encapsula los hiperparámetros $(\gamma, \lambda, C_{\text{abst}}, p_{\text{safe}}, \tau_{\text{avail\_min}}, B)$ y flags de ablación (`enforce_benign_guard`, `enable_availability`, `enable_asymmetric_cost`, `enable_abstention`, `enable_information_value`).
- **`TransitionLog` y `RAEAExecutionResult`:** Estructuras inmutables con serialización JSON para registro forense y trazabilidad completa de los valores $\mathcal{Q}(a)$.

### 1.2. `risk.py` (`RiskEstimator`)
- Evalúa los riesgos condicionales de Bayes:
  $$\mathcal{R}(a_{\text{phish}} \mid p) = C_{FP} \cdot (1 - p)$$
  $$\mathcal{R}(a_{\text{benign}} \mid p) = \begin{cases} \gamma \cdot C_{FP} \cdot p & \text{si pasa Guarda Benigna} \\ +\infty & \text{si viola Guarda Benigna en } t=0 \end{cases}$$
  $$\mathcal{R}(a_{\text{abstain}} \mid p) = C_{\text{abst}}$$
- Implementa `estimate_posterior_risk`: calcula la esperanza matemática del riesgo residual tras la adquisición considerando la probabilidad de éxito $\pi_m$ y la cota de fallback en caso de fallo.

### 1.3. `availability.py` (`AvailabilityEstimator`)
- Carga el modelo calibrado `artifacts/raea/availability_estimator.joblib`.
- Recibe exclusivamente el vector léxico inicial $x_0$ disponible en $S_0$.
- Retorna $\pi_m(x_0) \in [0.01, 0.99]$.
- Soporta desactivación controlada mediante `config.enable_availability=False` para estudios de ablación (retornando $1.0$).

### 1.4. `cost.py` (`AcquisitionCostEstimator`)
- Carga `artifacts/raea/cost_parameters.json` con las latencias y costes empíricos medidos en red real.
- Calcula el coste esperado amortizado:
  $$\mathbb{E}[\mathcal{C}(m) \mid x_0] = \pi_m(x_0) \cdot c_m^{\text{succ}} + (1 - \pi_m(x_0)) \cdot c_m^{\text{fail}}$$

### 1.5. `policy.py` (`ActionSelector`, `RiskAvailabilityAwarePolicy`, `AbstentionHandler`)
- Implementa el criterio de minimización óptima:
  $$a^* = \arg\min_{a \in \mathcal{A}(S_t)} \mathcal{Q}(a \mid S_t)$$
- Aplica restricciones de orden estricto entre modalidades ($M0 \to M1 \to M2 \to M3$).
- Prohíbe adquisiciones si el coste esperado supera el presupuesto restante o si la disponibilidad estimada es inferior a $\tau_{\text{avail\_min}}$.

### 1.6. `logger.py` (`DecisionLogger`)
- Registra cada decisión secuencial con los valores de $\mathcal{Q}(a)$, latencias observadas y razones analíticas, exportando a formato JSONL para auditoría científica.

### 1.7. `engine.py` (`run_raea`, `decide_next_raea`)
- **`run_raea`:** Bucle autónomo de inferencia adaptativa.
- **`decide_next_raea`:** Función de interfaz idéntica a `decide_next` de `phishguard_orchestrator.engine`, permitiendo que el worker de FastAPI ejecute la política RAEA mediante el flag de entorno `PHISHGUARD_ORCHESTRATOR_POLICY=raea` sin alterar el comportamiento de producción.

---

## 2. Validación de Integración y Pruebas Unitarias

El archivo `tests/test_raea_policy.py` valida exhaustivamente:
1. Detección precisa de factores de riesgo léxico (`is_ip_host`, `is_shortener`, homógrafos Punycode, etiquetas excesivas).
2. Bloqueo estricto de salidas benignas prematuras en $M0$ cuando existen indicios de evasión.
3. Autorización de salida benigna ultrarrápida cuando la URL es completamente limpia ($p_0 \le 0.02$).
4. Detención inmediata por alta certeza de phishing ($p_0 \ge 0.98$).
5. Activación de adquisición secuencial de red ante ambigüedad con presupuesto disponible.
6. Activación de abstención protectora cuando se agota el presupuesto o la evidencia es inconcluyente.
7. Compatibilidad hacia atrás con el bucle del worker de FastAPI.
8. Ejecución completa end-to-end con resolución de falso negativo silenciado.

**Resultado de pruebas:** 8 pruebas pasadas en 0.75 s. Batería histórica de pruebas (`tests/test_orchestrator.py` y `test_corrections_phase2.py`): 71 pruebas pasadas, 0 fallos.
