# Informe de Resultados Verificados: Comparación Estadística, Baselines y Ablaciones
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Evidencia Experimental — Fase 5: Comparación Estadística, Baselines y Estudios de Ablación*

---

## 1. Resumen de Tablas de Resultados

Se presentan las tablas cuantitativas completas generadas por [`run_statistical_comparison.py`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/run_statistical_comparison.py) sobre las $N=691$ observaciones de prueba independientes (*host_unseen*).

---

## 2. Comparación Integral de Baselines (Tabla Principal)

Extraído directamente de [`baseline_comparison.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/baseline_comparison.csv):

| Línea Base (*Baseline*) | Cobertura (%) | Abstención (%) | Accuracy | Precision | Recall | F1-Score [IC 95%] | FPR | FNR | Modalidades Medias | HTML Ahorrado (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A: $M_0$ Léxico Fijo** | 100.0% | 0.0% | 0.9291 | 0.9080 | 0.8272 | **0.8658** [0.8278, 0.9011] | 0.0320 | 0.1728 | 1.000 | **100.0%** |
| **B: $M_1$ Infraestructura Fijo** | 100.0% | 0.0% | 0.9609 | 0.9824 | 0.8743 | **0.9252** [0.8937, 0.9512] | **0.0060** | 0.1257 | 2.000 | **100.0%** |
| **C: $M_2$ Monolítico DOM** | 100.0% | 0.0% | 0.9638 | 0.9770 | 0.8901 | **0.9315** [0.9036, 0.9565] | 0.0080 | 0.1099 | 3.000 | 0.0% |
| **D: Cascada Original ($M_4$)** | 100.0% | 0.0% | 0.9595 | 0.9822 | 0.8691 | **0.9222** [0.8943, 0.9499] | **0.0060** | 0.1309 | 1.851 | **75.83%** |
| **E: Cascada Margen Simple** | 100.0% | 0.0% | 0.9493 | 0.9815 | 0.8325 | **0.9008** [0.8643, 0.9305] | **0.0060** | 0.1675 | **1.402** | **94.65%** |
| **F1: Cascada Asimétrica (Pol. C)**| 100.0% | 0.0% | 0.9638 | 0.9826 | 0.8848 | **0.9311** [0.9028, 0.9574] | **0.0060** | 0.1152 | 2.169 | **67.87%** |
| **F2: Cascada Selectiva (Pol. D)\***| **96.38%** | **3.62%** | **0.9745** | **1.0000** | **0.9034** | **0.9493** [0.9235, 0.9714] | **0.0000** | **0.0966** | 1.851 | **75.83%** |

*\*Nota Baseline F2: Evaluado estrictamente sobre las 666 muestras decididas (cobertura del 96.38%). En las 25 muestras abstenidas (3.62%), el sistema delega la decisión a revisión por analistas del SOC.*

---

## 3. Matriz de Estudios de Ablación Controlados

Extraído de [`ablation_study.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/ablation_study.csv):

| ID | Pregunta Científica Evaluada | Referencia vs Condición Manipulada | F1 Ref. | F1 Abl. | $\Delta F_1$ | $\Delta$ Prec. | $\Delta$ Rec. | $\Delta$ FPR | Conclusión Epistémica |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **ABL-01** | Impacto de suprimir salida temprana | Cascada Original vs $M_2$ Monolítico | 0.9222 | 0.9315 | **+0.0093** | -0.0052 | +0.0210 | +0.0020 | Salida temprana ahorra 75.8% HTML con coste ínfimo de F1 (-0.009). |
| **ABL-02** | Beneficio de permitir abstención | Cascada Forzada vs Cascada Rechazo | 0.9222 | 0.9493 | **+0.0271** | **+0.0178** | +0.0343 | **-0.0060** | Abstención en 3.6% de casos alcanza 100% de precisión sin falsos positivos. |
| **ABL-03A**| Umbral fijo 0.50 vs óptimo en $M_0$ | $M_0$ con $\tau^*=0.3827$ vs $\tau=0.50$ | 0.8658 | 0.8814 | **+0.0156** | +0.0491 | -0.0104 | -0.0180 | Umbral ingenuo 0.50 castiga el recall ante clases desbalanceadas. |
| **ABL-03B**| Umbral fijo 0.50 vs óptimo en $M_2$ | $M_2$ con $\tau^*=0.3950$ vs $\tau=0.50$ | 0.9315 | 0.9252 | **-0.0063** | +0.0054 | **-0.0158** | -0.0020 | Umbral calibrado recupera 6 ataques adicionales en $M_2$. |
| **ABL-04** | Restricción asimétrica en benignos | Cascada Simétrica B vs Asimétrica C | 0.9222 | 0.9311 | **+0.0089** | +0.0004 | **+0.0157** | 0.0000 | Evita salidas benignas prematuras en $M_0$, reduciendo FN de 25 a 19. |
| **ABL-05A**| Ganancia incremental de Infraestructura | $M_0$ Léxico vs $M_1$ Infra | 0.8658 | 0.9252 | **+0.0594** | **+0.0744** | +0.0471 | **-0.0260** | **Mayor ganancia del sistema:** $+5.94\%$ F1 y $-81\%$ FPR sin red HTML. |
| **ABL-05B**| Ganancia incremental de Contenido DOM | $M_1$ Infra vs $M_2$ DOM | 0.9252 | 0.9315 | **+0.0063** | -0.0054 | +0.0158 | +0.0020 | Ganancia moderada ($+0.6\%$ F1) a cambio de transferir HTML. |
| **ABL-06** | Entropía Shannon vs Margen Lineal | Cascada Margen Simple vs Entropía | 0.9008 | 0.9222 | **+0.0214** | +0.0007 | +0.0366 | 0.0000 | Entropía ofrece mejor balance entre recall y adquisiciones evitadas. |

---

## 4. Pruebas Inferenciales Pareadas y Prueba de No-Inferioridad

Extraído de [`paired_statistics.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/paired_statistics.csv):

| Contraste Pareado | Discordancias ($b / c$) | Estadístico $\chi^2$ | $p$-valor Raw | $p$-valor FDR (BH) | $\Delta F_1$ Medio [IC 95%] | Margen $\delta$ | No-Inferioridad Confirmada |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cascada Orig. vs $M_2$ Completo** | 1 / 4 | 0.8000 | 0.3750 | 0.5250 | -0.0091 [-0.0234, +0.0022] | -0.02 | NO (Límite inf. $-0.0234 \le -0.02$) |
| **Cascada Asim. vs $M_2$ Completo** | 1 / 1 | 0.5000 | 1.0000 | 1.0000 | **-0.0004** [-0.0085, +0.0074] | -0.02 | **SÍ (Límite inf. $-0.0085 > -0.02$)** |
| **Cascada Asim. vs Cascada Orig.** | 3 / 0 | 1.3333 | 0.2500 | 0.4375 | +0.0090 [0.0000, +0.0206] | — | — |
| **Cascada Orig. vs $M_0$ Léxico** | 25 / 4 | 13.7931 | $0.000104$ | **$0.000364$** | **+0.0566** [+0.0297, +0.0862] | — | SÍ (Superioridad estadísticamente sig.) |
| **$M_1$ Infra vs $M_0$ Léxico** | 24 / 2 | 16.9615 | $1.0 \times 10^{-5}$ | **$7.0 \times 10^{-5}$** | **+0.0597** [+0.0348, +0.0877] | — | SÍ (Superioridad estadísticamente sig.) |
| **$M_2$ Completo vs $M_1$ Infra** | 8 / 6 | 0.0714 | 0.7905 | 0.9223 | +0.0062 [-0.0137, +0.0270] | — | NO (Diferencia no significativa) |
| **Cascada Margen vs Cascada Orig.**| 1 / 8 | 4.0000 | 0.0391 | 0.0911 | -0.0214 [-0.0391, -0.0062] | — | NO (Margen simple es inferior a Entropía) |

---

## 5. Calibración Probabilística por Deciles

Extraído de [`calibration_analysis.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/calibration_analysis.csv):

| Nivel de Modelo | Error Calibración Esperado ($\text{ECE}$) | Error Máximo ($\text{MCE}$) | Brier Score | Calibración Válida ($\text{ECE} < 0.05$) |
| :--- | :---: | :---: | :---: | :---: |
| **$M_0$ Léxico** | 0.0862 | 0.3181 | 0.0636 | NO (Descalibración en colas extremas) |
| **$M_1$ Infraestructura** | **0.0238** | 0.5634 | 0.0361 | **SÍ (Excelente calibración)** |
| **$M_2$ Contenido DOM** | **0.0194** | 0.4379 | 0.0290 | **SÍ (Calibración sobresaliente)** |
| **$M_3$ Visual** | **0.0169** | 0.4654 | 0.0285 | **SÍ (Calibración sobresaliente)** |

---
*Fin del informe de resultados verificados — Fase 5: Comparación Estadística y Estudios de Ablación.*
