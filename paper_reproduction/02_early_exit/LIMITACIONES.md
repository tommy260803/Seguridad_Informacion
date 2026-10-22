# Informe de Limitaciones Científicas y Metodológicas: Cascada y Salida Temprana
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Transparencia Científica — Fase 2: Cascada Adaptativa y Abstención*

---

## 1. Alcance y Naturaleza de las Limitaciones

La optimización de costos en pipelines progresivos de aprendizaje automático mediante decisiones tempranas y abstención selectiva introduce compromisos inherentes que deben ser explicitados con rigor académico. Este documento presenta las limitaciones observadas en la evaluación empírica de las 5 políticas de cascada.

---

## 2. Inventario de Limitaciones Específicas

### 2.1. No Linealidad entre Modalidades Lógicas Ahorradas y Tiempo Real de Pared (*Wall-Clock Latency*)
- **Fenómeno:** La Política B y la Política C reducen las adquisiciones de HTML en un 75.83% y 67.87%, respectivamente. Sin embargo, esto **no se traduce en una reducción idéntica del tiempo de respuesta del usuario final**.
- **Causa Técnica:** En la etapa $M_1$ (Infraestructura), la resolución de registros DNS múltiples, handshake TLS y consulta a bases de datos de reputación introduce una latencia mediana de red que oscila entre 800 ms y 1,400 ms. Si bien se evita descargar y parsear el árbol DOM de $M_2$ (que consumiría entre 200 ms y 2,500 ms adicionales según el tamaño de la página), la latencia acumulada para muestras que llegan a $M_1$ sigue estando dominada por el retardo de red de Internet.
- **Advertencia Editorial:** En el manuscrito debe evitarse la afirmación simplista de que "el sistema es un 75% más rápido"; la afirmación rigurosa es que "evita el 75% del procesamiento y renderizado de contenido HTML, con una reducción del 54.3% en la latencia mediana de pared ($P_{50}$ pasa de 1,313 ms a 600 ms)".

### 2.2. Riesgo de Salida Temprana ante Evasión Léxica Sofisticada
- **Fenómeno:** Ataques de phishing que emplean nombres de dominio comprometidos legítimos o subdominios breves en proveedores reputados (e.g., `shakugxgd.github.io` o `mfacebook.com.vn`) exhiben una estructura sintáctica limpia. Esto hace que el modelo puramente léxico $M_0$ asigne una probabilidad de phishing cercana a cero ($p_0 < 0.02$).
- **Impacto:** Bajo la Política B (simétrica), esta baja probabilidad genera una entropía pequeña ($H \le 0.15$), lo que desencadena una salida temprana como benigno y produce un falso negativo inadvertido.
- **Mitigación y su Coste:** La Política C mitiga este riesgo restringiendo drásticamente la salida benigna en $M_0$ ($p_0 \le 0.005$). Sin embargo, esto obliga a inspeccionar $M_1$ para un mayor volumen de sitios, incrementando la latencia mediana de 600 ms a 1,162 ms.

### 2.3. Carga Operacional de la Clasificación Selectiva en Tráfico Masivo (Política D)
- **Fenómeno:** La Política D alcanza una precisión sobresaliente del 100.0% (0 falsos positivos en muestras decididas) al abstenerse en 25 casos de 691 (tasa de abstención del 3.62%).
- **Impacto Operacional:** Aunque un 3.62% es un valor excelente en un benchmark de laboratorio, en un despliegue de producción que procese 1,000,000 de URLs diarias, implicaría derivar **36,200 transacciones diarias** a revisión por analistas del Centro de Operaciones de Seguridad (SOC).
- **Tratamiento Alternativo:** Las variantes totalmente automatizadas *Fail-Closed* y *Fail-Open* resuelven este cuello de botella humano pero sacrifican métricas clave: *Fail-Closed* eleva los falsos positivos ($\text{FPR} = 2.0\%$), mientras que *Fail-Open* eleva los falsos negativos ($\text{FNR} = 16.75\%$).

### 2.4. Sensibilidad a la Calibración Probabilística Inter-Modelo
- **Fenómeno:** El criterio de salida temprana se basa en la entropía de Shannon $H(p)$, la cual asume que las probabilidades $p_k$ emitidas por cada modelo ($M_0, M_1, M_2$) representan probabilidades posteriores bien calibradas.
- **Riesgo:** Si un clasificador sufre de sobreconfianza (un error de calibración esperado $\text{ECE} > 0.05$), la entropía será artificialmente baja, engañando al mecanismo de parada temprana. En PhishPe, los valores de ECE se mantuvieron bajos ($\text{ECE} \approx 0.02-0.03$), pero cambios en la distribución subyacente de tráfico (*covariate shift*) podrían descalibrar las probabilidades y afectar la estabilidad del umbral $H_{esc}$.

### 2.5. Restricción al Subconjunto Complete-Case ($N=691$)
- **Fenómeno:** Para garantizar comparaciones estrictamente pareadas y justas entre las 5 políticas (donde la Política A requiere que $M_2$ esté disponible para todas las muestras), la evaluación se restringió a las 691 URLs de la partición *host_unseen* con adquisición multimodal completa.
- **Sesgo Muestral:** Sitios que sufrieron caídas de conexión durante la adquisición histórica de HTML no forman parte de este conjunto pareado. Si bien esta exclusión es metodológicamente obligatoria para el emparejamiento estadístico, los sistemas en producción deben contemplar políticas de fallo ante timeouts de red.
