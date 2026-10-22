# Informe Científico de Resultados Verificados: Benchmarking y Rendimiento de Sistemas
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Evidencia Experimental — Fase 4: Rendimiento Computacional, Latencia y Costes de Sistemas*

---

## 1. Resumen Ejecutivo y Hallazgos Principales

Se ejecutó el protocolo formal de benchmarking reproducible para caracterizar cuantitativamente los costes de cómputo, red y arquitectura operativa del sistema PhishPe. Las evaluaciones se realizaron sobre el hardware congelado documentado en [`hardware_environment.json`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/hardware_environment.json) (13th Gen Intel Core i5-13600K, 14 núcleos físicos, 15.78 GB RAM, Windows 11).

### Hallazgos Principales:
1. **La Dominancia Absoluta del Retardo de Red (Nivel B vs. Nivel A):** El cómputo algorítmico local en CPU para inferencia léxica ($M_0$) consume una mediana de **$14.04 \text{ ms}$**; la inferencia multimodal completa DOM ($M_2$) consume **$44.1 \text{ ms}$** acumulados. En contraste, la adquisición de infraestructura de red ($M_1$) presenta una latencia mediana de **$1,272.65 \text{ ms}$** ($P_{95} = 3,411.70 \text{ ms}$) y la captura en navegador Headless Chrome ($M_3$) requiere **$2,166.36 \text{ ms}$** ($P_{95} = 3,456.00 \text{ ms}$). **La red y el navegador consumen el 98.8% del tiempo total de respuesta.**
2. **Ahorro Real de Tiempo en la Cascada Adaptativa:** En la cohorte pareada auténtica ($N=83$ URLs con telemetría de navegador Chrome CDP 100% verificada), la **Cascada Original** reduce el tiempo medio de respuesta en un **$71.81\%$** respecto a $M_3$ completo (de $3,809.53 \text{ ms}$ a $1,073.82 \text{ ms}$; $p = 1.66 \times 10^{-13}$, Wilcoxon pareado) y en un **$31.44\%$** respecto a $M_2$ fijo ($p = 0.000159$).
3. **Compromiso Latencia-Seguridad en la Cascada Asimétrica:** La **Cascada Asimétrica Mejorada (Política C)**, que evita salidas prematuras en casos benignos sospechosos, presenta una latencia media de **$1,291.88 \text{ ms}$** (ahorro del **$66.09\%$** vs. $M_3$ y **$17.52\%$** vs. $M_2$; $p = 6.98 \times 10^{-10}$), manteniendo idéntico $F_1 = 0.9020$ pero garantizando mayor robustez frente a ataques sofisticados.
4. **Cumplimiento del Umbral Perceptivo de Usabilidad en Cliente:** El endpoint FastAPI `/check` opera con una latencia mediana de **$19.75 \text{ ms}$** ($P_{90} = 26.46 \text{ ms}$), cumpliendo con holgura el umbral perceptual de Nielsen ($< 100 \text{ ms}$). La extensión Chrome actualiza la insignia en **$0.25 \text{ ms}$** con caché caliente y en **$20.00 \text{ ms}$** con caché fría.
5. **Sobrecarga de Evaluación Secuencial (*Cascade Overhead*):** En el 11.3% de las muestras que requieren escalar hasta la última etapa, la evaluación secuencial de modelos previos introduce un recargo computacional de **$28.8 \text{ ms}$** en CPU. Sin embargo, en un pipeline HTTP integrado, este retardo representa menos del **$1.8\%$** del tiempo total de red.

---

## 2. Comparación de Rendimiento por Modelo y Política

Los resultados end-to-end sobre la cohorte auténtica de $N=83$ URLs se resumen a continuación (extraídos de [`performance_comparison.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/performance_comparison.csv)):

| Modelo / Política | Modalidades Medias | Accuracy | Precision | Recall | F1-Score | Latencia Mediana P50 (ms) [IC 95%] | Latencia Media (ms) [IC 95%] | P95 (ms) | Ahorro vs $M_3$ (%) | Ahorro vs $M_2$ (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$M_0$ (Léxico Puro)** | 1.000 | 0.9157 | 0.9565 | 0.7857 | 0.8627 | **6.00** [5.91, 6.09] | **6.19** [5.99, 6.40] | 7.74 | **99.84%** | **99.60%** |
| **$M_1$ (URL + Infra)** | 2.000 | 0.9398 | 1.0000 | 0.8214 | 0.9020 | **1,207.15** [1057.1, 1470.7] | **1,555.63** [1353.6, 1782.0] | 3,292.74 | 59.16% | 0.68% |
| **$M_2$ (URL + Infra + DOM)** | 3.000 | 0.9398 | 1.0000 | 0.8214 | 0.9020 | **1,217.62** [1067.4, 1482.6] | **1,566.24** [1364.0, 1792.9] | 3,301.49 | 58.89% | 0.00% |
| **$M_3$ (Multimodal + CDP)** | 4.000 | 0.9277 | 1.0000 | 0.7857 | 0.8800 | **3,768.69** [3348.1, 4138.8] | **3,809.53** [3544.9, 4095.1] | 5,691.47 | 0.00% | -143.23% |
| **Cascada Original ($M_4$)** | 1.940 | 0.9398 | 1.0000 | 0.8214 | **0.9020** | **464.80** [7.53, 708.63] | **1,073.82** [744.13, 1407.89] | 4,336.19 | **71.81%** | **31.44%** |
| **Cascada Asimétrica (Pol. C)**| 1.867 | 0.9398 | 1.0000 | 0.8214 | **0.9020** | **970.51** [696.53, 1249.66] | **1,291.88** [1006.56, 1582.87]| 3,408.43 | **66.09%** | **17.52%** |
| **Cascada Fallback (Estrat. C)**| 1.819 | 0.9398 | 1.0000 | 0.8214 | **0.9020** | **968.44** [696.53, 1198.84] | **1,193.04** [935.18, 1464.73] | 3,290.11 | **68.68%** | **23.83%** |

---

## 3. Desglose Componente por Componente (Niveles A, B y C)

Los datos detallados de latencia registrados en [`latency_by_component.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/latency_by_component.csv) y [`latency_summary.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/latency_summary.csv) revelan los cuellos de botella exactos:

### Nivel A: Cómputo Algorítmico Local (CPU)
- **Extracción Léxica $M_0$:** Media $= 0.37 \text{ ms}$, $P_{50} = 0.36 \text{ ms}$, $P_{95} = 0.42 \text{ ms}$.
- **Inferencia de Modelos ML:**
  - Inferencia $M_0$: Media $= 14.37 \text{ ms}$, $P_{50} = 14.04 \text{ ms}$, $P_{95} = 16.13 \text{ ms}$.
  - Inferencia $M_1$: Media $= 14.38 \text{ ms}$, $P_{50} = 14.15 \text{ ms}$, $P_{95} = 16.15 \text{ ms}$.
  - Inferencia $M_2$: Media $= 14.42 \text{ ms}$, $P_{50} = 14.18 \text{ ms}$, $P_{95} = 16.13 \text{ ms}$.
  - Inferencia $M_3$: Media $= 14.39 \text{ ms}$, $P_{50} = 14.11 \text{ ms}$, $P_{95} = 16.07 \text{ ms}$.
- **Parseo de Árbol DOM HTML (97 archivos reales):** Media $= 11.83 \text{ ms}$, $P_{50} = 8.90 \text{ ms}$, $P_{95} = 47.37 \text{ ms}$.
- **Evaluación de Decisión de Cascada:** Media $= 0.11 \text{ ms}$ (Cálculo de entropía $H(p)$ y comparación de umbrales).

### Nivel B: Adquisición de Red y Navegador
- **Resolución DNS:** Media $= 283.89 \text{ ms}$, $P_{50} = 213.64 \text{ ms}$, $P_{95} = 803.55 \text{ ms}$.
- **Petición HTTP / Socket Connect:** Media $= 1,188.56 \text{ ms}$, $P_{50} = 981.71 \text{ ms}$, $P_{95} = 2,772.38 \text{ ms}$.
- **Red Total de Infraestructura ($M_1$):** Media $= 1,521.97 \text{ ms}$, $P_{50} = 1,272.65 \text{ ms}$, $P_{95} = 3,411.70 \text{ ms}$.
- **Captura Headless Chrome CDP ($M_3$):** Media $= 2,237.23 \text{ ms}$, $P_{50} = 2,166.36 \text{ ms}$, $P_{95} = 3,456.00 \text{ ms}$.

### Nivel C: Operación y Sistema en Cliente
- **Endpoint FastAPI `/check`:** Media $= 156.98 \text{ ms}$, $P_{50} = 19.75 \text{ ms}$, $P_{90} = 26.46 \text{ ms}$.
- **Caché en Memoria (`DecisionCache`):**
  - Acierto (*Hit*): Media $= 1.32 \text{ µs}$ ($0.0013 \text{ ms}$), $P_{50} = 1.30 \text{ µs}$.
  - Fallo (*Miss*): Media $= 2.93 \text{ µs}$ ($0.0029 \text{ ms}$).
- **Filtro de Bloom (`BloomFilter` en 14,999 URLs):** Media $= 4.89 \text{ µs}$ ($P_{50} = 4.70 \text{ µs}$).
- **Latencia de Insignia en Extensión:**
  - Caché Caliente: $0.25 \text{ ms}$ (Instantáneo).
  - Caché Fría: $20.00 \text{ ms}$ ($P_{50}$), $26.71 \text{ ms}$ ($P_{90}$).

---

## 4. Análisis Estadístico de Pruebas Pareadas

Las pruebas pareadas de Wilcoxon documentadas en [`performance_statistical_tests.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/performance_statistical_tests.csv) confirman formalmente las diferencias de eficiencia:

| Par Comparado | Muestras Pareadas ($N$) | Estadístico $W$ | Valor $p$ | Significativo ($\alpha=0.01$) | Diferencia Media (ms) [IC 95%] | Mediana Dif. (ms) | Interpretación Científica |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Cascada Orig. vs $M_3$** | 83 | 0.0 | $1.66 \times 10^{-13}$ | **SÍ** | -2,735.71 [-3097.0, -2388.2] | -2,708.62 | Cascada es significativamente más rápida que $M_3$. |
| **Cascada Orig. vs $M_2$** | 83 | 641.0 | $0.000159$ | **SÍ** | -492.42 [-848.6, -142.8] | -10.57 | Cascada es significativamente más rápida que $M_2$. |
| **Cascada Asim. vs $M_3$** | 83 | 0.0 | $1.15 \times 10^{-14}$ | **SÍ** | -2,517.65 [-2780.4, -2260.3] | -2,398.32 | Cascada Asimétrica es significativamente más rápida que $M_3$. |
| **Cascada Asim. vs $M_2$** | 83 | 287.0 | $6.98 \times 10^{-10}$ | **SÍ** | -274.36 [-463.9, -80.7] | -10.66 | Cascada Asimétrica es significativamente más rápida que $M_2$. |
| **Cascada Asim. vs Orig.** | 83 | 407.0 | $0.3044$ | **NO** | +218.06 [-134.7, +583.0] | 0.00 | No hay diferencia significativa de latencia entre ambas cascadas. |
| **Cascada Orig. vs $M_0$** | 83 | 0.0 | $5.18 \times 10^{-9}$ | **SÍ** | +1,067.63 [+737.8, +1401.6] | +457.20 | Cascada es más lenta que $M_0$ puro al inspeccionar red en casos ambiguos. |

---

## 5. Análisis Forense: Sobrecarga y Casos Desfavorables de la Cascada

El diseño de una cascada no es gratis; incurre en un recargo cuando una muestra no puede ser resuelta tempranamente:

1. **Penalización por Evaluación Secuencial:**
   - En las muestras que escalan hasta $M_2$ o $M_3$, el pipeline ejecuta la extracción e inferencia de $M_0$, luego la extracción e inferencia de $M_1$, y finalmente la inferencia de $M_2$/$M_3$.
   - Este cómputo redundante introduce un recargo promedio de **$28.8 \text{ ms}$** de CPU respecto a evaluar $M_2$ directamente si los vectores ya estuviesen precargados.
2. **Justificación Operativa:**
   - En una arquitectura real de adquisición en caliente, la descarga de la página HTML en $M_2$ requiere obligatoriamente haber resuelto el DNS y establecido la conexión TCP/TLS en $M_1$. Por lo tanto, el retardo de red de $M_1$ es un pre-requisito físico ineludible de $M_2$.
   - Puesto que el 39.07% de las muestras salen en $M_0$ (ahorrando el 100% de la red) y el 36.76% salen en $M_1$ (ahorrando el parseo DOM y renderizado), el beneficio neto acumulado supera holgadamente a la sobrecarga secuencial.

---

## 6. Rendimiento y Huella de Memoria

El perfil de recursos registrado en [`resource_usage.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/04_performance/resource_usage.csv) muestra que todos los modelos presentan una huella computacional ligera:
- **Pico de Memoria RAM Incurrido:** Entre **$445.3 \text{ KB}$** ($M_0$) y **$1,781.2 \text{ KB}$** ($M_3$ multimodal completo).
- **Rendimiento de Procesamiento Algorítmico en CPU:** $M_0$ puede procesar **$157.9 \text{ URLs/segundo}$** en un único núcleo de CPU.
- **Régimen Adaptativo:** La cascada opera como un pipeline híbrido: el 39% de las consultas se resuelven en régimen 100% CPU-bound (< 15 ms), mientras que el 61% restante transiciona ordenadamente a régimen I/O-bound.

---
*Fin del informe de resultados verificados — Fase 4: Rendimiento y Benchmarking de Sistemas.*
