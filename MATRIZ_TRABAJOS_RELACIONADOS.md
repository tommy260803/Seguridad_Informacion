# MATRIZ_TRABAJOS_RELACIONADOS.md: Comparativa Taxonómica del Estado del Arte

**Método:** RAEA-Phish vs. Enfoques Relevantes de la Literatura Científica  
**Dimensiones Evaluadas:**
1. **Criterio de Decisión** (Incertidumbre, Ganancia de Información, Riesgo de Bayes, Heurística).
2. **Modelado de Costes** (Uniforme, Fijo por Modalidad, Asimétrico $C_{FN}/C_{FP}$, Latencia).
3. **Consciencia de Disponibilidad** (Asume 100% disponible vs. Modela probabilidad de fallo/caída).
4. **Política de Salida Temprana** (Simétrica, Restringida/Asimétrica, Ninguna/Estática).
5. **Mecanismo de Abstención** (Sin abstención, Umbral fijo a posteriori, Selectivo integrado).
6. **Dominio de Aplicación** (Visión/NLP general, Diagnóstico médico, Detección de Phishing Web).

---

## 1. Matriz Comparativa Sistemática

| Trabajo / Autor(es) | Criterio de Decisión | Modelado de Costes | Consciencia de Disponibilidad | Política de Salida Temprana | Mecanismo de Abstención | Dominio Principal |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Trapeznikov & Saligrama (AISTATS 2013)** | Cascada multietapa basada en margen de clasificador | Coste presupuestado acumulado estático ($\sum c_i \le B$) | No (asume adquisición perfecta 100%) | Simétrica basada en margen | No | Clasificación general (visión / tabular) |
| **Wang et al. (ICML 2014) - LP-Cascade** | Minimización de coste empírico acotado | Coste monetario/computacional por característica | No (disponibilidad perfecta) | Simétrica por umbral de confianza | No | Reconocimiento de dígitos y texto |
| **Geifman & El-Yaniv (NeurIPS 2017) - SelectiveNet** | Optimización de cobertura con garantía de riesgo acotado | Sin costes de adquisición de modalidades | N/A (modalidad única estática) | N/A | Sí (función de selección integrada) | Visión por computadora (CIFAR, ImageNet) |
| **Ma et al. (ICML 2019) - EDDI** | Información Mutua y Variational Autoencoders | Coste uniforme por característica adquirida | No (asume características disponibles bajo demanda) | Simétrica cuando la información adicional es nula | No | Diagnóstico clínico y datos tabulares |
| **Teerapittayanon et al. (ICPR 2016) - BranchyNet** | Entropía de salida en capas intermedias de CNN | Latencia de inferencia por capa de red | N/A (red fija) | Simétrica por umbral de entropía | No | Clasificación de imágenes |
| **Opara et al. (Computers & Security 2020)** | Clasificador monolítico multimodal (URL + DOM) | Ninguno (computa todas las variables) | Imputación estática de fallos de red | No (pipeline forzado) | No | Detección de Phishing Web |
| **Marchal et al. (IEEE TDSC 2017) - Off-the-Hook** | Filtro escalonado (lista blanca $\to$ léxico $\to$ búsqueda DNS/Google) | Heurística secuencial ad-hoc | Trata fallos como indeterminados | Parada temprana ad-hoc en listas blancas | No | Detección de Phishing Web en navegador |
| **PhishPe / PhishGuard Pro (Baseline M5, 2026)** | Entropía de Shannon simétrica ($H(p) \le 0.15$) | Coste unitario abstracto por modalidad ($c_m = 1.0$) | No (consulta ciega independientemente de disponibilidad) | Simétrica ($H(p) \le 0.15$ para ambas clases) | Sí (al final si $H(p) > 0.20$ o $0.50$) | Detección de Phishing Web adaptativo |
| **RAEA-Phish (Propuesto en este estudio)** | **Minimización de Riesgo Posterior de Bayes + Coste Ponderado por Disponibilidad** | **Coste Asimétrico $C_{FN} \gg C_{FP}$ + Latencia Operativa Real** | **Sí: Estimador Calibrado $P(\text{avail}_m \mid x_0)$** | **Asimétrica: Guarda estricta contra falsos negativos prematuros en $M0$** | **Sí: Calibrado y sensible al riesgo/presupuesto restante** | **Detección de Phishing Web en Cascada Multimodal** |

---

## 2. Diferenciación Crítica frente al Baseline Directo (M5 de PhishPe)

El baseline M5 de PhishPe representaba un avance frente a clasificadores monolíticos al ahorrar latencia mediante parada por entropía. Sin embargo, sufre de tres deficiencias estructurales que RAEA-Phish resuelve:
1. **Simetría errónea en la salida temprana:** M5 permite clasificar una URL como benigna con la misma facilidad que clasificarla como phishing ($p \le 0.024 \iff H \le 0.15$). En ciberseguridad, un falso negativo permite la intrusión, mientras que un falso positivo solo eleva la consulta a la siguiente etapa. RAEA-Phish impone una política de riesgo asimétrico.
2. **Ceguera a la disponibilidad:** Si un host está caído o bloqueado, M5 gasta tiempo intentando descargar el contenido DOM o renderizarlo en sandbox, generando timeouts innecesarios. RAEA-Phish predice la disponibilidad antes de invocar la modalidad.
3. **Desacoplamiento entre incertidumbre y coste:** M5 usa la entropía como único árbitro, ignorando el trade-off explícito entre el riesgo de error residual y el coste computacional/tiempo incurrido.
