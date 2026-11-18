# PROTOCOLO CIENTÍFICO CONGELADO Y PRE-REGISTRO
## Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad (RAEA-Phish)

**Fecha de congelamiento:** 2026-10-22  
**Estado:** CONGELADO / PROSPECTIVO  
**Repositorio:** `https://github.com/tommy260803/Seguridad_Informacion`  
**Rama experimental:** `research/risk-aware-policy`  
**Commit base congelado:** `2910b6a4495c5068761af40f08efceaf123a4b08`  
**Rama histórica de referencia:** `corrections-phase2` (commit `058169a99786a42203d7db27d5da994b6ceb61c9`)  

---

## 1. Justificación y Propósito del Pre-Registro

Este protocolo formaliza el **congelamiento estricto** de todos los clasificadores, estimadores de disponibilidad, calibradores de coste, hiperparámetros de decisión bayesiana y presupuestos operacionales de RAEA-Phish con anterioridad al análisis del conjunto de prueba independiente ($N=240$).

Queda **expresamente prohibido** cualquier reajuste de umbrales, reentrenamiento de modelos base o modificación de funciones de coste motivado por la inspección de las etiquetas de la cohorte prospectiva. Todas las comparaciones estadísticas se computarán de forma prospectiva bajo las condiciones exactas aquí registradas.

---

## 2. Manifiesto Criptográfico de Componentes y Modelos Congelados

Todos los artefactos ejecutables y de configuración quedan congelados bajo los siguientes hashes SHA-256:

| Componente | Tipo / Descripción | Ruta en Repositorio | SHA-256 |
| :--- | :--- | :--- | :--- |
| **Configuración Maestra** | Hiperparámetros operacionales y costes | `configs/raea_final_experiment.json` | `28abd43a768e3c5cd136cf069846ebbfe319a51670e18f328632ab1ed25b6073` |
| **Motor RAEA** | Núcleo de adquisición adaptativa | `src/phishguard_orchestrator/raea/engine.py` | `d54c15f8624be15c4bed3a2b5f167d4905a58cfeca41de8e9a5e9dc30cc2a3b9` |
| **Modelos de Datos** | Estructuras de decisión y transición | `src/phishguard_orchestrator/raea/models.py` | `7981320855a4aa34268004518632e884c579784f096b716694b2f200bb66f00b` |
| **Función de Riesgo** | Cálculo bayesiano de riesgo esperado | `src/phishguard_orchestrator/raea/risk.py` | `72c9c4c306a10dac5dadcf705c5727ad3b64149fcd2e4a087e0367290ed5ae07` |
| **Adaptador Orquestador** | Interfaz con sensores de adquisición | `src/phishguard_orchestrator/raea/adapter.py` | `dcefe1a00fb75868cdec73741570f53685c724d8e8ba09a202a7ac25d4313618` |
| **Estimador Disponibilidad** | Modelo logístico entrenado en `train_avail` | `artifacts/raea/availability_estimator.joblib` | `0e029aeed8ebbb6ac5b2829a593a19e943cf7f88428559aae68091cfad32df59` |
| **Clasificador $M_0$** | Modelo léxico congelado (ITE/Real) | `artifacts/m0-ite-real/model.joblib` | *(verificado en manifiesto histórico)* |
| **Clasificador $M_1$** | Modelo léxico + infraestructura (ITE/Real) | `artifacts/m1-ite-real/model.joblib` | *(verificado en manifiesto histórico)* |
| **Clasificador $M_2$** | Modelo multimodal léxico + red + HTML | `artifacts/m2-ite-real/model.joblib` | *(verificado en manifiesto histórico)* |
| **Clasificador $M_3$** | Modelo visual auténtico CDP | `artifacts/corrected_audit/m3-authentic-cdp/model.joblib` | `39198a362da18e819bb8a0a79748d35e4694b037f2cf7cf534bf58c167ef0de3` |

---

## 3. Parámetros Operacionales Congelados

Se fijan de forma inmutable los siguientes parámetros de decisión:

1. **Matriz de Pérdida Asimétrica (Riesgo Terminal):**
   - Coste de Falso Positivo ($C_{\text{fp}}$): $1.000$
   - Factor de Severidad de Falso Negativo ($\gamma$): $15.000$ (un falso negativo equivale a 15 falsos positivos).
   - Coste de Falso Negativo ($C_{\text{fn}} = \gamma \cdot C_{\text{fp}}$): $15.000$
   - Coste de Verdadero Positivo / Verdadero Negativo: $0.000$

2. **Coste y Política de Abstención:**
   - Coste unitario de abstención ($C_{\text{abst}}$): $0.350$
   - Semántica: Remisión inmediata a triaje humano o sandbox defensivo ante incertidumbre epistémica no reducible económicamente.

3. **Costes Normalizados de Adquisición Multimodal ($C_{\text{acq}}$):**
   - $M_0$ (Léxico / URL): $0.050$ (coste basal de CPU local, latencia < 10 ms).
   - $M_1$ (Infraestructura de red / DNS / TLS): $0.250$ (tráfico de red, latencia media 150–250 ms).
   - $M_2$ (Contenido HTML / DOM / Scripts): $0.400$ (descarga HTTP, parseo DOM, latencia media 400–800 ms).
   - $M_3$ (Inspección Visual / Renderizado CDP): $0.300$ (render headless en navegador, latencia 800–1500 ms).
   - Ponderador de coste de adquisición en la función objetivo ($\lambda_{\text{cost}}$): $1.000$
   - Presupuesto máximo acumulado de adquisición ($B_{\text{max}}$): $1.000$

4. **Reglas de Salvaguarda y Salida Segura:**
   - Umbral de salida benigna segura en $M_0$: $p_{\text{safe}} = 0.0200$ (permite terminación inmediata como legítimo solo si la probabilidad posterior de phishing es $\le 2\%$).
   - Fallback ante fallo de disponibilidad: En caso de timeout o error en infraestructura o contenido, el orquestador degrada la inferencia a la última probabilidad modal disponible sin bloquear el pipeline.

---

## 4. Comparadores de Referencia Congelados

Se evaluarán de forma pareada las siguientes 6 políticas basales concurrentes:

1. **$M_0$ Fijo (Solo Léxico):**
   - Evalúa únicamente la URL. Cobertura obligatoria 100%, 1.000 modalidades solicitadas.
2. **$M_1$ Fijo (Léxico + Red):**
   - Solicita siempre red. Ante fallo de red usa fallback $M_0$. Cobertura obligatoria 100%, 2.000 modalidades solicitadas.
3. **$M_2$ Fijo (Léxico + Red + Contenido):**
   - Solicita siempre red y descarga de contenido. Cobertura obligatoria 100%, 3.000 modalidades solicitadas.
4. **$B_3$ (Cascada Basada en Entropía Simétrica - Thrun / Trapeznikov):**
   - Termina tempranamente en $M_0$ si $H(p_0) \le 0.150$. Si no, solicita red ($M_1$); si $H(p_1) \le 0.150$ termina en $M_1$. Si persiste la incertidumbre, solicita $M_2$.
5. **$B_4$ (Cascada Conservadora Asimétrica):**
   - Salvaguarda benigna en $M_0$: solo permite salida temprana legítima si $p_0 \le 0.020$. Para phishing exige $p_0 \ge 0.850$.
6. **$B_5$ (Clasificación Selectiva de Chow sobre $M_1$):**
   - Solicita siempre red ($M_1$). Decide entre `{phishing, legítimo, abstención}` minimizando directamente el riesgo bayesiano:
     $$\text{Decisión} = \arg\min \{ C_{\text{fp}}(1-p), \gamma C_{\text{fp}} p, C_{\text{abst}} \}$$

---

## 5. Diseño Experimental de la Nueva Evaluación Externa Independiente

### 5.1. Población Experimental Prospectiva ($N=240$)
A diferencia de la cohorte retrospectiva inicial ($N=118$, 80 positivas, 38 negativas), la cohorte prospectiva independiente se diseña con un esquema balanceado ($1:1$, prevalencia $50\%$) para maximizar la potencia estadística y la precisión en la tasa de falsos positivos:
- **Total de observaciones:** $N = 240$
- **Clase Positiva (Phishing Web Verificado):** $N_{\text{pos}} = 120$
  - Provenientes exclusivamente de feeds de phishing web activo: OpenPhish ($n=40$), CERT.PL ($n=40$), Phishing Army ($n=40$).
  - **Criterio de exclusión estricto:** Exclusión de malware genérico (ejecutables, scripts de URLhaus, binarios `.exe`, `.apk`, `.sh`).
- **Clase Negativa (Controles Legítimos Diversos):** $N_{\text{neg}} = 120$
  - No restringida a páginas de inicio de dominios de alta popularidad.
  - HIPO Universities ($n=40$): sitios universitarios con rutas profundas y subdominios institucionales.
  - CISA .gov ($n=40$): portales gubernamentales con formularios de acceso interno y estructuras complejas.
  - Majestic Million ($n=40$): sitios comerciales e institucionales de tráfico medio y alto.

### 5.2. Garantías de Validez y Ausencia de Fuga de Datos
- **Solapamiento de dominios con entrenamiento (`samples.csv`):** **0 / 240 (0%)**.
- **Solapamiento de dominios con cohorte retrospectiva ($N=118$):** **0 / 240 (0%)**.
- **Diversidad de dominios:** 240 dominios registrados completamente disjuntos.

### 5.3. Justificación del Tamaño Muestral y Potencia Estadística
1. **Precisión de la Tasa de Falsos Positivos (FPR):**
   - En $N_{\text{neg}} = 38$ (retrospectivo), cada falso positivo representa $2.63\%$ de FPR, con un intervalo de Wald al 95% de $\pm 5.1\%$.
   - Con $N_{\text{neg}} = 120$ (prospectivo), cada falso positivo representa $0.83\%$ de FPR, reduciendo el semi-ancho del intervalo de confianza al $95\%$ a $\approx \pm 2.8\%$.
2. **Potencia en Reducción de Costes (H3):**
   - Para un tamaño de efecto pareado observado $\Delta = -0.1424$ con $\sigma_{\Delta} \approx 0.20$, el test pareado a dos colas con $\alpha = 0.05$ alcanza una potencia estadística estimada $> 99.9\%$ con $N=240$.

---

## 6. Pre-Registro de Hipótesis y Criterios de Aceptación

Las hipótesis formales registradas son:

1. **Hipótesis H3 (Eficiencia de Adquisición):**
   $$H_0: C_{\text{acq}}(\text{RAEA}) \ge C_{\text{acq}}(M_1) \quad \text{vs} \quad H_1: C_{\text{acq}}(\text{RAEA}) < C_{\text{acq}}(M_1)$$
   - *Criterio de aceptación:* Reducción estadísticamente significativa en coste normalizado pareado ($p_{\text{Holm}} < 0.05$) mediante Bootstrap ($B=5,000$).
2. **Hipótesis H1 (Reducción de Riesgo Penalizado vs $M_1$):**
   $$H_0: R_{\text{pen}}(\text{RAEA}) \ge R_{\text{pen}}(M_1) \quad \text{vs} \quad H_1: R_{\text{pen}}(\text{RAEA}) < R_{\text{pen}}(M_1)$$
   - *Criterio de aceptación:* $p_{\text{Holm}} < 0.05$ mediante Bootstrap pareado ($B=5,000$).
3. **Hipótesis H2 (Comparación de Riesgo vs Política Selectiva $B_5$):**
   $$H_0: R_{\text{pen}}(\text{RAEA}) \ge R_{\text{pen}}(B_5) \quad \text{vs} \quad H_1: R_{\text{pen}}(\text{RAEA}) < R_{\text{pen}}(B_5)$$
   - *Criterio de verificación:* Contraste no sesgado. En caso de no alcanzarse superioridad frente a $B5$ (debido a que $B5$ opera con red no penalizada), se reportará con total transparencia que la ventaja de RAEA radica en el compromiso de coste y latencia, no en riesgo absoluto frente a un clasificador selectivo omnisciente de red.

---

## 7. Declaración de Integridad y Trazabilidad

Este protocolo fue redactado y congelado antes de ejecutar la evaluación comparativa sobre la cohorte $N=240$. Los resultados subsiguientes se presentarán sin alteraciones 'ad-hoc'.
