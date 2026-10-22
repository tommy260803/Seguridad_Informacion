# PROTOCOLO_ENTRENAMIENTO.md: Protocolo de Entrenamiento y Calibración

**Método:** RAEA-Phish  
**Componentes Entrenados:** Estimadores de Disponibilidad ($\pi_{\text{infra}}, \pi_{\text{content}}$) y Calibradores de Probabilidad  

---

## 1. Algoritmo y Arquitectura de los Estimadores de Disponibilidad

Para predecir la probabilidad de éxito de adquisición $\pi_m(x_0) = P(\mathbf{s}_m = \text{success} \mid x_0)$ se seleccionó una arquitectura lineal regularizada con calibración post-hoc:
- **Modelo Base:** Regresión Logística con penalización $L_2$ ($C=0.2$, optimizador L-BFGS, `random_state=42`).
- **Espacio de Características:** Vector de 9 dimensiones derivado de la URL y la inferencia $M0$:
  $$\mathbf{z}_0 = [\text{len}(host), \text{len}(url), H_{\text{host}}, \mathbb{I}(\text{is\_ip}), \mathbb{I}(\text{https}), p_{M0}, n_{\text{dots}}, n_{\text{labels}}, n_{\text{subdomains}}]$$
- **Calibración Probabilística:** Escalamiento de Platt mediante `CalibratedClassifierCV(method='sigmoid', cv=3)` ajustado estrictamente sobre la partición `train_avail` ($N=300$).

---

## 2. Protocolo de Extracción de Parámetros de Coste y Latencia

Los parámetros de latencia empírica se derivaron de los sondeos reales de red medidos con reloj monotónico en la partición de desarrollo:
- **Infraestructura ($m_1$):**
  - Éxito ($c_{\text{succ}}$): Consulta DNS completa y handshake TLS $\implies \mu = 1,509.1\text{ ms}, \sigma = 992.1\text{ ms}$, coste normalizado $= 0.20$.
  - Fallo ($c_{\text{fail}}$): DNS error o socket timeout $\implies \mu = 1,180.2\text{ ms}$, coste normalizado $= 0.80$.
- **Contenido DOM ($m_2$):**
  - Éxito ($c_{\text{succ}}$): Descarga HTTP y parseo DOM $\implies \mu = 1,957.1\text{ ms}$, coste normalizado $= 0.50$.
  - Fallo ($c_{\text{fail}}$): HTTP 404/500 o timeout $\implies \mu = 1,005.0\text{ ms}$, coste normalizado $= 1.20$.
- **Visual CDP ($m_3$):**
  - Éxito ($c_{\text{succ}}$): Renderizado completo en sandbox $\implies \mu = 1,782.4\text{ ms}$, coste normalizado $= 1.50$.
  - Fallo ($c_{\text{fail}}$): Sandbox timeout $\implies \mu = 2,510.0\text{ ms}$, coste normalizado $= 2.50$.

---

## 3. Protocolo de Ajuste de Hiperparámetros de la Política RAEA

Todos los hiperparámetros operativos se fijaron en la partición `train_avail` mediante búsqueda en rejilla con validación cruzada:
- **$\gamma = C_{FN} / C_{FP}$:** Evaluado en $\{5, 10, 15, 20, 30\}$. El valor nominal $\gamma = 15.0$ minimizó la pérdida esperada ponderada protegiendo contra falsos negativos sin saturar el número de falsas alarmas.
- **$\lambda$:** Evaluado en $\{0.10, 0.25, 0.50, 1.0\}$. El valor $\lambda = 0.25$ ofreció el mejor compromiso entre ahorro computacional y retención de evidencia crítica.
- **$p_{\text{safe}}$:** Evaluado en $\{0.01, 0.02, 0.05\}$. Fijado analíticamente en $p_{\text{safe}} = 0.02$, concordante con la cota de Bayes $\frac{C_{\text{abst}}}{\gamma + 1} = \frac{0.35}{16} \approx 0.0218$.
- **$\tau_{\text{avail\_min}}$:** Fijado en $0.10$ para evitar invocaciones con menos del 10% de probabilidad de éxito.
