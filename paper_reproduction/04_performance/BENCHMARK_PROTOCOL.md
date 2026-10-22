# Protocolo Experimental de Benchmarking y Rendimiento de Sistemas
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Metodología y Reproducibilidad — Fase 4: Rendimiento Computacional, Latencia y Costes de Sistemas*

---

## 1. Justificación y Objetivos de la Evaluación

En la literatura de detección de phishing mediante aprendizaje automático, es común asumir de manera ingenua que reducir el número de etapas o adquisiciones lógicas en una cascada progresiva equivale automáticamente a un ahorro porcentual idéntico de tiempo de pared (*wall-clock latency*), consumo de CPU o memoria RAM. 

El objetivo de este protocolo es diseñar, formalizar y ejecutar un benchmark controlado e independiente para comparar la eficiencia real entre:
1. Modelos monomodales y multimodales fijos ($M_0, M_1, M_2, M_3$).
2. La cascada simétrica original ($M_4$).
3. Las mejores políticas adaptativas obtenidas en fases previas:
   - Cascada Asimétrica Optimizada (Política C de Fase 2).
   - Cascada con Fallback Operativo ante Indisponibilidad de Red (Estrategia C de Fase 3).
4. La arquitectura de servicio en tiempo real (FastAPI, caché en memoria y extensión Chrome).

---

## 2. Entorno Experimental y Especificaciones de Hardware

Para garantizar la estricta reproducibilidad de las mediciones, el benchmark se ejecutó sobre un entorno local de cómputo congelado, cuyas especificaciones se registraron en [`hardware_environment.json`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/hardware_environment.json):

- **Procesador (CPU):** 13th Gen Intel(R) Core(TM) i5-13600K (14 núcleos físicos: 6 Performance-cores + 8 Efficient-cores; 20 hilos lógicos).
- **Memoria RAM:** 15.78 GB totales (DDR5, canal dual).
- **Sistema Operativo:** Microsoft Windows 11 Pro (Build 10.0.26200, arquitectura AMD64).
- **Entorno de Ejecución:** Python 3.12.10 (CPython de 64 bits).
- **Versiones de Paquetes Clave:**
  - `scikit-learn`: 1.7.2
  - `numpy`: 2.4.6
  - `scipy`: 1.15.3
  - `joblib`: 1.5.3
  - `fastapi`: 0.141.1
  - `pydantic`: 2.13.5
  - `httpx`: 0.28.1
  - `matplotlib`: 3.10.8
  - `playwright`: 1.64.0

---

## 3. Taxonomía de Medición por Niveles (Separación Estricta)

Para evitar la contaminación cruzada entre el retardo de red de Internet y la complejidad algorítmica local, las mediciones se segmentaron estrictamente en tres niveles independientes:

```
┌────────────────────────────────────────────────────────────────────────┐
│ NIVEL A: CÓMPUTO ALGORÍTMICO LOCAL (CPU / RAM)                          │
│  - Extracción léxica M0 (< 0.4 ms)      - Inferencia M0 (~14.4 ms)     │
│  - Mapeo de infraestructura M1 (< 0.2 ms) - Inferencia M1 (~14.4 ms)   │
│  - Parseo DOM y contenido M2 (8.9 ms)    - Inferencia M2 (~14.4 ms)    │
│  - Mapeo visual M3 (< 0.1 ms)            - Inferencia M3 (~14.4 ms)    │
│  - Decisión de cascada (entropía de Shannon + umbrales, ~0.1 ms)       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ NIVEL B: ADQUISICIÓN DE RED Y NAVEGADOR (I/O BOUND)                     │
│  - Resolución DNS (Mediana: 213.6 ms, P95: 803.5 ms)                   │
│  - Petición HTTP / TLS Handshake (Mediana: 981.7 ms, P95: 2,772.4 ms)  │
│  - Red total infraestructura M1 (Mediana: 1,272.7 ms, P95: 3,411.7 ms) │
│  - Captura y renderizado Chrome CDP M3 (Mediana: 2,166.4 ms, P95: 3,456.0 ms) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ NIVEL C: OPERACIÓN END-TO-END Y ARQUITECTURA DE CLIENTE                │
│  - Endpoint FastAPI /check (Mediana P50: 19.8 ms)                      │
│  - Caché de Decisiones (DecisionCache Hit: 1.3 µs, Miss: 2.9 µs)       │
│  - Filtro de Bloom (Lookup en 14,999 URLs: 4.89 µs)                    │
│  - Renderizado de Insignia en Extensión Chrome:                        │
│      * Con Caché Caliente: 0.25 ms (Instantáneo)                       │
│      * Con Caché Fría: 20.0 ms (Totalmente conforme Nielsen < 100 ms)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Comparadores Evaluados

Se evaluaron siete configuraciones de inferencia bajo condiciones de prueba idénticas sobre la cohorte auténtica de $N=83$ URLs (con captura Chrome CDP 100% verificada) y sobre la cohorte Complete-Case de $N=691$ URLs:

1. **$M_0$ (Léxico Puro):** Clasificación basada exclusivamente en sintaxis de URL. Cero peticiones de red ($N_{\text{mod}}=1.0$).
2. **$M_1$ (URL + Infraestructura):** Inspección léxica más resolución DNS y cabeceras de red ($N_{\text{mod}}=2.0$).
3. **$M_2$ (Multimodal URL + Infra + DOM):** Incorpora descarga y parseo de árbol HTML DOM ($N_{\text{mod}}=3.0$).
4. **$M_3$ (Multimodal Completo + Chrome CDP):** Incorpora captura de pantalla en navegador Headless Chrome y características visuales ($N_{\text{mod}}=4.0$).
5. **Cascada Original ($M_4$ Simétrica):** Escalamiento adaptativo con criterio de Shannon $H(p) \le 0.15$.
6. **Cascada Asimétrica Mejorada (Política C de Fase 2):** Salida conservadora para benignos ($p_0 \le 0.005$) y agresiva para phishing ($p_0 \ge 0.85$), minimizando falsos negativos.
7. **Cascada con Fallback Operativo (Estrategia C de Fase 3):** Cascada progresiva con degradación a $M_0$ ante caídas o timeouts de red.

---

## 5. Fórmulas Matemáticas y Definiciones Estadísticas

### 5.1. Ahorro Relativo de Tiempo
El ahorro relativo respecto a una política de referencia se calcula estrictamente sobre magnitudes homogéneas:

$$\text{Ahorro (\%)} = 100 \times \frac{\bar{T}_{\text{referencia}} - \bar{T}_{\text{propuesta}}}{\bar{T}_{\text{referencia}}}$$

*Restricción metodológica:* Solo se aplica cuando $\bar{T}_{\text{referencia}} > 0$ y ambos escenarios provienen de poblaciones pareadas equivalentes (cohorte $N=83$).

### 5.2. Entropía de Shannon para Salida Temprana
La incertidumbre de la predicción en la etapa $k$ con probabilidad de phishing $p_k \in [0, 1]$ se cuantifica mediante:

$$H(p_k) = - p_k \log_2(p_k) - (1 - p_k) \log_2(1 - p_k)$$

con la convención estándar $0 \log_2 0 = 0$.

### 5.3. Intervalos de Confianza por Bootstrap
Para cada métrica (media y mediana), se generaron intervalos de confianza al 95% ($CI_{95\%}$) mediante remuestreo con reemplazo de $B = 1,000$ réplicas estratificadas:

$$\alpha = \frac{1 - 0.95}{2} = 0.025 \implies [q_{0.025}, q_{0.975}]$$

### 5.4. Pruebas Pareadas no Paramétricas (Wilcoxon Signed-Rank Test)
Dada la marcada asimetría y cola larga en la distribución de latencias de red, se utilizó la prueba de rangos con signo de Wilcoxon para muestras pareadas:

$$W = \min(W^+, W^-), \quad \text{donde } W^+ = \sum_{d_i > 0} R_i, \quad W^- = \sum_{d_i < 0} R_i$$

donde $d_i = T_{i, \text{política 1}} - T_{i, \text{política 2}}$ representa la diferencia de latencia pareada para la muestra $i$, y $R_i$ es el rango de $|d_i|$. Se estableció un nivel de significancia estricto de $\alpha = 0.01$.

---

## 6. Control de Calentamiento (*Warm-up*) y Gestión de Caché

1. **Fase de Calentamiento:** Antes de registrar telemetría, se ejecutaron 10 ciclos completos de inferencia sobre muestras de descarte para estabilizar la compilación JIT de bibliotecas C, cargar estructuras de datos en memoria caché L3 y precargar el árbol de sufijos públicos (`public_suffix_list.dat`) y el índice Tranco Top 1M.
2. **Control de Caché de Decisiones:**
   - **Medición Fría (*Cold Cache*):** Cada evaluación de muestra en los comparadores $M_0-M_3$ y cascadas se ejecutó sin reutilizar resultados previos en memoria.
   - **Medición Caliente (*Warm Cache*):** Se evaluó el impacto de la caché en memoria (`DecisionCache` con política LRU y TTL de 180 segundos) mediante un flujo sintético de 10,000 consultas bajo distribución Zipf ($\alpha = 1.15$), simulando la distribución de popularidad de sitios en navegación real.

---
*Fin del documento de protocolo de benchmark — Fase 4: Rendimiento y Eficiencia de Sistemas.*
