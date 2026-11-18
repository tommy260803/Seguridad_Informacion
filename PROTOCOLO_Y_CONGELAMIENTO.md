# PROTOCOLO EXPERIMENTAL Y CONGELAMIENTO CIENTÍFICO (PRE-REGISTRO INTERNO)
## Proyecto PhishPe / RAEA-Phish
**Título de la Investigación:**  
*"Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad"*

**Fecha y Hora de Congelamiento:** 2026-10-22T19:00:00-05:00  
**Estado:** PROTOCOLO INTERNO FECHADO E INMUTABLE  
**Repositorio Oficial:** `https://github.com/tommy260803/Seguridad_Informacion`  
**Rama de Desarrollo:** `research/risk-aware-policy`  
**Commit Base Congelado:** `2910b6a4495c5068761af40f08efceaf123a4b08`  
**Rama Histórica de Referencia:** `corrections-phase2` (commit `058169a99786a42203d7db27d5da994b6ceb61c9`)  

---

## 1. Declaración de Independencia y Alcance

Este documento constituye el **protocolo interno fechado de congelamiento metodológico** para la evaluación del algoritmo RAEA-Phish. 
Se deja constancia explícita de que este pre-registro es de naturaleza **técnica e interna del equipo de investigación**; no constituye un registro institucional ante una entidad de acreditación externa.

Queda estrictamente prohibido:
1. Reentrenar o ajustar los modelos clasificadores base ($M_0, M_1, M_2, M_3$).
2. Modificar umbrales de decisión o calibradores logísticos tras observar las etiquetas de prueba.
3. Modificar la matriz de costes asimétricos o la penalización de abstención para optimizar métricas 'ad-hoc'.
4. Seleccionar muestras de prueba basándose en las puntuaciones emitidas por el detector.

---

## 2. Manifiesto Criptográfico de Artefactos y Modelos Congelados

Todos los componentes de inferencia se encuentran congelados bajo los siguientes identificadores y hashes SHA-256:

| Componente | Tipo | Ubicación en Repositorio | SHA-256 |
| :--- | :--- | :--- | :--- |
| **Configuración Maestra** | Hiperparámetros JSON | `configs/raea_final_experiment.json` | `28abd43a768e3c5cd136cf069846ebbfe319a51670e18f328632ab1ed25b6073` |
| **Motor Algorítmico RAEA** | Código Python | `src/phishguard_orchestrator/raea/engine.py` | `d54c15f8624be15c4bed3a2b5f167d4905a58cfeca41de8e9a5e9dc30cc2a3b9` |
| **Modelos de Decisión** | Código Python | `src/phishguard_orchestrator/raea/models.py` | `7981320855a4aa34268004518632e884c579784f096b716694b2f200bb66f00b` |
| **Estimador de Riesgo** | Código Python | `src/phishguard_orchestrator/raea/risk.py` | `72c9c4c306a10dac5dadcf705c5727ad3b64149fcd2e4a087e0367290ed5ae07` |
| **Adaptador Orquestador** | Código Python | `src/phishguard_orchestrator/raea/adapter.py` | `dcefe1a00fb75868cdec73741570f53685c724d8e8ba09a202a7ac25d4313618` |
| **Estimador Disponibilidad** | Modelo Joblib | `artifacts/raea/availability_estimator.joblib` | `0e029aeed8ebbb6ac5b2829a593a19e943cf7f88428559aae68091cfad32df59` |
| **Clasificador $M_0$** | Léxico (URL) | `artifacts/m0-ite-real/model.joblib` | `249e6e387e74d842b3312470fe7a8f548f86908c9447e8c54c9b41676c938912` |
| **Clasificador $M_1$** | Red (DNS/TLS) | `artifacts/m1-ite-real/model.joblib` | `c139ebe5dc042d7558a30d2bdd85016b279e4557324a40231f663062597316d9` |
| **Clasificador $M_2$** | Contenido (HTML) | `artifacts/m2-ite-real/model.joblib` | `9da6de033d70318397ab2d973f44dedaee42156d51b57a00113fdbc8ec6a8400` |
| **Clasificador $M_3$** | Visual (CDP) | `artifacts/corrected_audit/m3-authentic-cdp/model.joblib` | `39198a362da18e819bb8a0a79748d35e4694b037f2cf7cf534bf58c167ef0de3` |

---

## 3. Parámetros de Decisión y Costes Operacionales Inmutables

1. **Pérdida Asimétrica Bayesiana:**
   - Coste de Falso Positivo ($C_{\text{fp}}$): $1.000$
   - Multiplicador de Falso Negativo ($\gamma$): $15.000$ (un falso negativo equivale a 15 falsos positivos).
   - Coste de Falso Negativo ($C_{\text{fn}} = \gamma \cdot C_{\text{fp}}$): $15.000$
   - Coste de Decisión Correcta ($TP = TN$): $0.000$

2. **Coste y Criterio de Abstención:**
   - Coste unitario de abstención ($C_{\text{abst}}$): $0.350$
   - Regla de Chow: Se emite decisión selectiva si $\min(C_{\text{fp}}(1-p), \gamma C_{\text{fp}} p) < C_{\text{abst}}$; en caso contrario, el sistema se abstiene y transfiere la muestra a revisión analítica.

3. **Costes Normalizados de Adquisición Multimodal:**
   - $M_0$ (Léxico URL): $0.000$ (coste basal de CPU local).
   - $M_1$ (Red / DNS / TLS): Éxito = $0.200$, Fallo / Timeout = $0.800$.
   - $M_2$ (Contenido HTML / DOM): Éxito = $0.500$, Fallo / Timeout = $1.200$.
   - $M_3$ (Visual / Renderizado): Éxito = $0.300$.

4. **Reglas de Salvaguarda:**
   - Umbral de salida benigna segura: $p_{\text{safe}} = 0.0200$.

---

## 4. Políticas de Comparación Obligatorias

1. **$B_0\_M_0$ Fijo:** Inferencia basada exclusivamente en la URL. Cobertura obligatoria 100%.
2. **$B_1\_M_1$ Fijo:** Inferencia basada en URL + Red. Cobertura obligatoria 100%. Fallback a $M_0$ ante fallo de red.
3. **$B_2\_M_2$ Fijo:** Inferencia basada en URL + Red + Contenido. Cobertura obligatoria 100%.
4. **$B_3\_entropy$:** Cascada simétrica de entropía ($H \le 0.150$). Cobertura 100%.
5. **$B_4\_conservative$:** Cascada asimétrica ($p_0 \le 0.020$ o $p_0 \ge 0.850$). Cobertura 100%.
6. **$B_5\_M1\_chow$:** Clasificación selectiva convencional de Chow sobre $M_1$. Permite abstención.
7. **RAEA-Phish ($B_6$):** Política adaptativa con estimación de disponibilidad y valor esperado de información.

---

## 5. Tratamiento Riguroso de Abstenciones

Se establecen 3 escenarios de evaluación experimental obligatorios:
1. **Evaluación Selectiva (`selective`):**
   - Las abstenciones no emiten predicción binaria.
   - Las métricas ($TP, FP, TN, FN, \text{Precision}, \text{Recall}, F1$) se computan exclusivamente sobre las $N_{\text{decided}}$ observaciones decididas.
   - Se reporta la cobertura: $\text{Coverage} = N_{\text{decided}} / N$.
2. **Decisión Forzada Fail-Open (`failopen`):**
   - Toda abstención se clasifica como **LEGÍTIMA (0)** (la página se deja pasar).
   - Las abstenciones de sitios phishing se convierten en **Falsos Negativos ($FN$)**.
   - Las abstenciones de sitios legítimos se convierten en **Verdaderos Negativos ($TN$)**.
   - Cobertura obligatoria: $100\%$.
3. **Decisión Forzada Fail-Closed (`failclosed`):**
   - Toda abstención se clasifica como **SOSPECHOSA / PHISHING (1)** (la página se bloquea / alerta).
   - Las abstenciones de sitios phishing se convierten en **Verdaderos Positivos ($TP$)**.
   - Las abstenciones de sitios legítimos se convierten en **Falsos Positivos ($FP$)**.
   - Cobertura obligatoria: $100\%$.

---

## 6. Pre-Registro de Hipótesis Estadísticas

1. **Hipótesis H1 (Reducción de Riesgo RAEA vs $M_1$):**
   $$H_0: R_{\text{pen}}(\text{RAEA}) \ge R_{\text{pen}}(M_1) \quad \text{vs} \quad H_1: R_{\text{pen}}(\text{RAEA}) < R_{\text{pen}}(M_1)$$
   - *Procedimiento:* Bootstrap pareado ($B=5,000$), corrección de Holm ($\alpha = 0.05$).
2. **Hipótesis H2 (Comparación de Riesgo RAEA vs $B_5$):**
   $$H_0: R_{\text{pen}}(\text{RAEA}) \ge R_{\text{pen}}(B_5) \quad \text{vs} \quad H_1: R_{\text{pen}}(\text{RAEA}) < R_{\text{pen}}(B_5)$$
   - *Directriz de honestidad:* En caso de que $B_5$ alcance menor riesgo cuando la red es gratuita e ilimitada, se rechazará H2 sin forzar conclusiones artificiales.
3. **Hipótesis H3 (Eficiencia de Coste RAEA vs $M_1$):**
   $$H_0: C_{\text{acq}}(\text{RAEA}) \ge C_{\text{acq}}(M_1) \quad \text{vs} \quad H_1: C_{\text{acq}}(\text{RAEA}) < C_{\text{acq}}(M_1)$$
   - *Directriz de honestidad:* Se evaluará el compromiso coste-cobertura y se reportará si el ahorro se mantiene en entornos benignos o si RAEA incrementa adquisiciones en corpus altamente hostiles.
