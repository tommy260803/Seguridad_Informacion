# FORMULACION_MATEMATICA.md: Formulación Matemática Rigurosa de RAEA-Phish

**Método:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Área:** Procesos de Decisión Secuencial Bajo Incertidumbre y Coste Asimétrico

---

## 1. Definición del Espacio de Estados y Observaciones

Sea una muestra web $x \in \mathcal{X}$ caracterizada por un conjunto de modalidades ordenadas por complejidad e intrusividad:
$$\mathcal{M} = \{m_0, m_1, m_2, m_3\} = \{\text{URL}, \text{Infraestructura}, \text{Contenido DOM}, \text{Visual CDP}\}$$

En el paso de decisión $t \in \{0, 1, 2, 3\}$, el sistema se encuentra en un estado $S_t$:
$$S_t = \left( x_{0:t}, \mathcal{M}_t, \mathbf{s}_t, p_t, B_t \right)$$
donde:
- $x_{0:t}$: vector de características extraído de las modalidades consultadas hasta el paso $t$. En particular, $x_0$ representa las características léxicas y de autoridad de la URL.
- $\mathcal{M}_t \subseteq \mathcal{M}$: subconjunto de modalidades ya consultadas ($\mathcal{M}_0 = \{m_0\}$).
- $\mathbf{s}_t \in \{\text{success}, \text{blocked}, \text{timeout}, \text{error}\}^{|\mathcal{M}_t|}$: vector de estados de adquisición observados.
- $p_t = P(y = 1 \mid x_{0:t}, \mathbf{s}_t) \in [0, 1]$: probabilidad posterior calibrada de que el sitio sea de phishing ($y = 1$), estimada por el modelo correspondiente a la etapa $t$ ($M_t$).
- $B_t \in \mathbb{R}_{\ge 0}$: presupuesto restante de latencia/coste (en milisegundos o unidades abstractas), con $B_{t+1} = B_t - c(a_t)$.

---

## 2. Espacio de Acciones Válidas

En cada estado $S_t$, el agente selecciona una acción $a \in \mathcal{A}(S_t)$:
$$\mathcal{A}(S_t) = \mathcal{A}_{\text{term}} \cup \mathcal{A}_{\text{acq}}(S_t)$$

1. **Acciones Terminales ($\mathcal{A}_{\text{term}}$):**
   - $a_{\text{phish}}$: Detener el análisis y emitir veredicto definitivo de **Phishing** ($\hat{y} = 1$).
   - $a_{\text{benign}}$: Detener el análisis y emitir veredicto definitivo de **Legítimo** ($\hat{y} = 0$).
   - $a_{\text{abstain}}$: Detener el análisis y emitir veredicto de **Abstención / Retención** ($\hat{y} = \bot$), activando advertencia preventiva o revisión humana.

2. **Acciones de Adquisición ($\mathcal{A}_{\text{acq}}(S_t)$):**
   - $a_{\text{infra}}$: Consultar infraestructura de red (DNS, IP, ASN, certificados TLS). Válida si $m_1 \notin \mathcal{M}_t$ y $\text{Coste}(m_1) \le B_t$.
   - $a_{\text{content}}$: Descargar y analizar el contenido HTML/DOM. Válida si $m_2 \notin \mathcal{M}_t$, $m_1 \in \mathcal{M}_t$ y $\text{Coste}(m_2) \le B_t$.
   - $a_{\text{visual}}$: Renderizar en sandbox Playwright y extraer características visuales. Válida si $m_3 \notin \mathcal{M}_t$, $m_2 \in \mathcal{M}_t$ y $\text{Coste}(m_3) \le B_t$.

---

## 3. Matriz de Costes Asimétricos y Riesgo de Bayes Terminal

La pérdida asociada a una predicción terminal $\hat{y}$ dado el estado verdadero $y \in \{0, 1\}$ se define mediante una matriz de costes asimétrica:

| Estado Verdadero | Predicción $\hat{y} = 0$ (Legítimo) | Predicción $\hat{y} = 1$ (Phishing) | Predicción $\hat{y} = \bot$ (Abstención) |
| :---: | :---: | :---: | :---: |
| **$y = 0$ (Legítimo)** | $0$ | $C_{FP}$ | $C_{\text{abst}}$ |
| **$y = 1$ (Phishing)** | $C_{FN}$ | $0$ | $C_{\text{abst}}$ |

Bajo el régimen de ciberseguridad, se cumple la condición estricta:
$$0 < C_{\text{abst}} \le C_{FP} \ll C_{FN}$$
En nuestro protocolo base normalizado:
$$C_{FP} = 1.0, \quad C_{FN} = \gamma \quad (\gamma \ge 1, \text{ valor típico } \gamma = 10 \text{ a } 20), \quad C_{\text{abst}} = 0.35$$

Para una probabilidad posterior estimada $p = P(y = 1 \mid S_t)$, el **Riesgo Condicional de Bayes** de cada acción terminal es:
$$\mathcal{R}(a_{\text{phish}} \mid p) = C_{FP} \cdot (1 - p)$$
$$\mathcal{R}(a_{\text{benign}} \mid p) = C_{FN} \cdot p = \gamma \cdot p$$
$$\mathcal{R}(a_{\text{abstain}} \mid p) = C_{\text{abst}}$$

El riesgo óptimo de decisión terminal inmediata es:
$$\mathcal{R}_{\text{term}}^*(S_t) = \min \left\{ \mathcal{R}(a_{\text{phish}} \mid p_t), \; \mathcal{R}(a_{\text{benign}} \mid p_t), \; \mathcal{R}(a_{\text{abstain}} \mid p_t) \right\}$$

---

## 4. Modelado Probabilístico de Disponibilidad de Modalidades

A diferencia de los modelos teóricos de adquisición de características donde las variables siempre existen, en la web viva la disponibilidad es estocástica.

Definimos la variable binaria indicadora de éxito de adquisición para la modalidad $m$:
$$V_m \in \{0, 1\}, \quad V_m = 1 \iff \mathbf{s}_m = \text{success}$$

La probabilidad condicional de disponibilidad se estima utilizando únicamente las características $x_0$ observables en la URL:
$$\pi_m(x_0) = P(V_m = 1 \mid x_0)$$
donde $\pi_m(x_0)$ es modelada por un estimador calibrado $g_m(x_0) \in [0, 1]$.

---

## 5. Coste Esperado de Consulta de Evidencia

Cada intento de adquisición de la modalidad $m$ involucra un coste computacional y de latencia que depende de si la consulta tiene éxito o falla por timeout/bloqueo:
$$\mathbb{E}[\mathcal{C}(a_m) \mid S_t] = \pi_m(x_0) \cdot c_m^{\text{success}} + (1 - \pi_m(x_0)) \cdot c_m^{\text{fail}}$$
donde $c_m^{\text{success}}$ es el coste promedio medido en milisegundos de una consulta exitosa, y $c_m^{\text{fail}}$ es el tiempo de espera por fallo o timeout (p. ej., socket timeout en TLS o timeout de descarga HTTP).

---

## 6. Riesgo Posterior Esperado y Valor de la Evidencia Adicional

Si se ejecuta la acción de adquisición $a_m$:
1. **Con probabilidad $\pi_m(x_0)$**, la modalidad $m$ se adquiere exitosamente ($V_m = 1$). El sistema transiciona a un nuevo vector de características $x_{0:t+1}$ y actualiza su creencia a $p_{t+1} = M_{t+1}(x_{0:t+1})$. El nuevo riesgo terminal esperado será $\mathbb{E}_{p_{t+1}}[\mathcal{R}_{\text{term}}^*(S_{t+1}) \mid V_m = 1]$.
2. **Con probabilidad $1 - \pi_m(x_0)$**, la modalidad falla ($V_m = 0$). No se obtiene nueva evidencia de contenido/red; la creencia se actualiza considerando el hecho mismo del fallo como evidencia o manteniéndose en el estado de respaldo con un incremento residual de incertidumbre:
   $$p_{t+1}^{\text{fail}} = p_t + \delta_{\text{fail}}(m, \mathbf{s}_m)$$

Por tanto, el **Riesgo Posterior Esperado** al intentar adquirir la modalidad $m$ es:
$$\mathbb{E}[\mathcal{R}(S_{t+1}) \mid S_t, a_m] = \pi_m(x_0) \cdot \mathbb{E}[\mathcal{R}_{\text{term}}^*(S_{t+1}) \mid V_m = 1] + (1 - \pi_m(x_0)) \cdot \mathcal{R}_{\text{term}}^*(S_t^{\text{fail}})$$

La función de valor de adquisición $\mathcal{Q}(a_m \mid S_t)$ equilibra el riesgo posterior esperado y el coste amortizado por el parámetro de compromiso $\lambda > 0$:
$$\mathcal{Q}(a_m \mid S_t) = \mathbb{E}[\mathcal{R}(S_{t+1}) \mid S_t, a_m] + \lambda \cdot \mathbb{E}[\mathcal{C}(a_m) \mid S_t]$$

---

## 7. Criterio de Selección Óptima de Acciones

La política RAEA selecciona la acción que minimiza el valor $\mathcal{Q}$:
$$a^*(S_t) = \arg\min_{a \in \mathcal{A}(S_t)} \mathcal{Q}(a \mid S_t)$$
donde para las acciones terminales:
$$\mathcal{Q}(a_{\text{term}} \mid S_t) = \mathcal{R}(a_{\text{term}} \mid p_t)$$

---

## 8. Guarda Asimétrica contra Salidas Benignas Prematuras

Para resolver la vulnerabilidad de las cascadas simétricas donde $H(p_0) \le 0.15$ detiene prematuramente URLs maliciosas camufladas, RAEA-Phish impone una **condición de guarda analítica** en $t = 0$:

> **Teorema de Guarda Benigna en $M0$:**  
> La acción $a_{\text{benign}}$ en $t=0$ es permitida **si y solo si**:
> $$p_0 \le p_{\text{safe}} = \frac{C_{\text{abst}}}{\gamma + 1} \quad \text{y} \quad \text{RiesgoLéxico}(x_0) = \text{False}$$
> donde $\text{RiesgoLéxico}(x_0)$ es una señal booleana que detecta factores de alto riesgo de evasión léxica:
> 1. Host es una dirección IP pura (`is_ip_host`).
> 2. Uso de acortador de URLs (`is_shortener`).
> 3. Dominio con homógrafos Punycode / IDN (`is_idn_punycode`).
> 4. Dominio no presente en Tranco Top-1M con entropía léxica elevada ($H_{\text{lex}} > 3.8$).

Si $p_0 > p_{\text{safe}}$ o $\text{RiesgoLéxico}(x_0) = \text{True}$, la acción $a_{\text{benign}}$ queda **estrictamente eliminada del espacio de acciones válidas $\mathcal{A}(S_0)$**, forzando al sistema a consultar infraestructura $m_1$ o abstenerse si el presupuesto está agotado.
