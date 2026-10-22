# FUNCION_DE_COSTE.md: Modelado de Costes Asimétricos y Optimización Multicriterio

**Método:** RAEA-Phish  
**Objetivo:** Cuantificar el trade-off formal entre el riesgo de error de clasificación y los costes operativos de adquisición de evidencia.

---

## 1. Función de Coste Total Operativo

El coste total de procesar una muestra $x$ mediante la trayectoria de decisiones $\tau = (a_0, a_1, \dots, a_T)$ con veredicto final $\hat{y} \in \{0, 1, \bot\}$ frente a la etiqueta verdadera $y \in \{0, 1\}$ se define como:
$$\mathcal{L}_{\text{total}}(\tau; y) = \mathcal{L}_{\text{error}}(\hat{y}, y) + \sum_{t=0}^{T-1} \mathcal{C}(a_t, \mathbf{s}_t)$$

---

## 2. Pérdida por Error de Clasificación ($\mathcal{L}_{\text{error}}$)

La pérdida por error refleja la asimetría intrínseca entre permitir un ataque de phishing y emitir una falsa alarma:
$$\mathcal{L}_{\text{error}}(\hat{y}, y) = 
\begin{cases}
0 & \text{si } \hat{y} = y \\
C_{FP} & \text{si } \hat{y} = 1 \land y = 0 \quad (\text{Falso Positivo}) \\
C_{FN} & \text{si } \hat{y} = 0 \land y = 1 \quad (\text{Falso Negativo}) \\
C_{\text{abst}} & \text{si } \hat{y} = \bot \quad (\text{Abstención / Retención})
\end{cases}$$

### Parámetros de Referencia Científica:
- **$C_{FP} = 1.0$ (Coste base unitario):** Una falsa alarma interrumpe la navegación del usuario mediante una pantalla de advertencia requiriendo confirmación.
- **$C_{FN} = \gamma \cdot C_{FP}$ con $\gamma \in [5, 50]$ (Valor nominal $\gamma = 15.0$):** Un falso negativo expone credenciales corporativas o personales a los atacantes, con un coste financiero y operativo significativamente superior.
- **$C_{\text{abst}} = 0.35$:** La abstención genera una advertencia preventiva de "Sitio Incierto / No Verificable", ofreciendo un nivel de protección intermedio sin bloquear determinantemente el recurso.

---

## 3. Coste de Adquisición de Modalidades ($\mathcal{C}(a_m, \mathbf{s}_m)$)

Para cada modalidad $m \in \{\text{infra}, \text{content}, \text{visual}\}$, el coste se desglosa según el resultado de la adquisición:

| Modalidad | Coste de Éxito ($c_m^{\text{succ}}$) | Coste de Fallo/Timeout ($c_m^{\text{fail}}$) | Latencia Media Experimental |
| :--- | :---: | :---: | :---: |
| **Infraestructura ($m_1$)** | 0.20 | 0.80 | $\approx 220\text{ ms}$ (éxito) vs. $800\text{ ms}$ (timeout) |
| **Contenido DOM ($m_2$)** | 0.50 | 1.20 | $\approx 450\text{ ms}$ (éxito) vs. $1,200\text{ ms}$ (error HTTP/timeout) |
| **Visual CDP ($m_3$)** | 1.50 | 2.50 | $\approx 1,800\text{ ms}$ (éxito) vs. $2,500\text{ ms}$ (sandbox timeout) |

### Coste Esperado de Consulta:
Dado el estimador de disponibilidad $\pi_m(x_0) = P(\mathbf{s}_m = \text{success} \mid x_0)$:
$$\mathbb{E}[\mathcal{C}(a_m) \mid x_0] = \pi_m(x_0) \cdot c_m^{\text{succ}} + (1 - \pi_m(x_0)) \cdot c_m^{\text{fail}}$$

Nótese que si $\pi_m(x_0)$ es bajo (p. ej., en un host con IP sospechosa que probablemente no responda a HTTP), el coste esperado se aproxima a $c_m^{\text{fail}}$, desincentivando intentos infructuosos que solo introducirían latencia muerta.

---

## 4. Función de Valor de Acción $\mathcal{Q}(a \mid S_t)$

En cada estado $S_t$ con creencia calibrada $p_t$:

1. **Para acciones terminales:**
   $$\mathcal{Q}(a_{\text{phish}} \mid S_t) = C_{FP} \cdot (1 - p_t) = 1.0 \cdot (1 - p_t)$$
   $$\mathcal{Q}(a_{\text{benign}} \mid S_t) = 
   \begin{cases}
   C_{FN} \cdot p_t = \gamma \cdot p_t & \text{si cumple Guarda Benigna} \\
   +\infty & \text{si viola Guarda Benigna en } t=0
   \end{cases}$$
   $$\mathcal{Q}(a_{\text{abstain}} \mid S_t) = C_{\text{abst}} = 0.35$$

2. **Para acciones de adquisición ($a_m$):**
   $$\mathcal{Q}(a_m \mid S_t) = \mathbb{E}[\mathcal{R}(S_{t+1}) \mid S_t, a_m] + \lambda \cdot \mathbb{E}[\mathcal{C}(a_m) \mid x_0]$$
   donde el parámetro $\lambda \in [0.1, 1.0]$ modula la aversión al coste/latencia según el perfil operativo.

---

## 5. Propiedades Analíticas de la Función de Coste

1. **Umbral de Decisión Phishing:** Si no se consulta más evidencia, clasificar como phishing es óptimo cuando $\mathcal{Q}(a_{\text{phish}}) \le \mathcal{Q}(a_{\text{benign}})$, lo que induce el umbral de Bayes asimétrico:
   $$1 - p_t \le \gamma \cdot p_t \implies p_t \ge \frac{1}{\gamma + 1}$$
   Para $\gamma = 15$, el umbral óptimo de detección de phishing es $p^* = \frac{1}{16} = 0.0625$. Esto contrasta drásticamente con el umbral ingenuo de $0.50$ de las cascadas convencionales.
2. **Justificación Económica de la Adquisición:** Una modalidad $m$ solo será consultada si la reducción esperada en el riesgo de error supera el coste penalizado:
   $$\mathcal{R}_{\text{term}}^*(S_t) - \mathbb{E}[\mathcal{R}(S_{t+1}) \mid S_t, a_m] > \lambda \cdot \mathbb{E}[\mathcal{C}(a_m) \mid x_0]$$
   Si la disponibilidad esperada $\pi_m(x_0)$ es muy baja, la reducción esperada del riesgo es casi nula y el coste de intento es elevado, por lo que la política descarta la consulta y prefiere una decisión conservadora o abstención.
