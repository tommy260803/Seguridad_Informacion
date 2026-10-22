# Resultados Experimentales Consolidados para Publicación
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Síntesis de Resultados Cuantitativos para el Autor/Redactor*

---

## 1. Resumen Tabular Maestro de Rendimiento de Modelos y Cascadas

Evaluación pareada homogénea sobre la partición independiente *host_unseen* ($N=691$ URLs con ground truth verificado: 191 phishing, 500 legítimas) con intervalos de confianza al 95% calculados mediante 2,000 réplicas de remuestreo bootstrap:

| Modelo / Política | Modalidades Medias | Cobertura (%) | Accuracy | Precision | Recall | F1-Score [IC 95%] | FPR | FNR | Ahorro HTML (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$M_0$ (Léxico Puro)** | 1.000 | 100.0% | 0.9291 | 0.9080 | 0.8272 | **0.8658** [0.8278, 0.9011] | 0.0320 | 0.1728 | **100.0%** |
| **$M_1$ (URL + Infra)** | 2.000 | 100.0% | 0.9609 | 0.9824 | 0.8743 | **0.9252** [0.8937, 0.9512] | **0.0060** | 0.1257 | **100.0%** |
| **$M_2$ (Monolítico DOM)** | 3.000 | 100.0% | 0.9638 | 0.9770 | 0.8901 | **0.9315** [0.9036, 0.9565] | 0.0080 | 0.1099 | 0.0% |
| **$M_3$ (Visual CDP, $N=83$)** | 4.000 | 100.0% | 0.9277 | 1.0000 | 0.7857 | **0.8800** [0.8000, 0.9412] | **0.0000** | 0.2143 | 0.0% |
| **Cascada Original ($M_4$)** | 1.851 | 100.0% | 0.9595 | 0.9822 | 0.8691 | **0.9222** [0.8943, 0.9499] | **0.0060** | 0.1309 | **75.83%** |
| **Cascada Asimétrica (Pol. C)**| 2.169 | 100.0% | 0.9638 | 0.9826 | 0.8848 | **0.9311** [0.9028, 0.9574] | **0.0060** | 0.1152 | **67.87%** |
| **Cascada Selectiva (Pol. D)\***| 1.851 | **96.38%** | **0.9745** | **1.0000** | **0.9034** | **0.9493** [0.9235, 0.9714] | **0.0000** | **0.0966** | **75.83%** |

*\*Nota: Cascada Selectiva evaluada sobre 666 muestras decididas (3.62% de abstención por incertidumbre elevada, derivado a SOC).*

---

## 2. Resultados Clave por Eje Temático

### 2.1. Inferencia Estadística y No-Inferioridad (Fase 5)
- **Análisis Exploratorio de No-Inferioridad:** La Cascada Asimétrica no muestra inferioridad estadística frente al modelo monolítico $M_2$ bajo un margen post-hoc de $\delta = 0.02$:
  $$\Delta F_1 = -0.0004 \quad [\text{IC}_{97.5\% \text{ unilateral}} = -0.0085 > -0.0200, \quad p < 0.001]$$
  *(Nota metodológica: al no mediar preespecificación formal del margen previa al análisis, se declara como análisis exploratorio generador de hipótesis).*
- **Salto Cualitativo de la Infraestructura ($M_0 \to M_1$):**
  $$\Delta F_1 = +0.0597 \quad [\text{IC}_{95\%}: +0.0348, +0.0877], \quad \chi^2 = 16.96, \quad p = 1.0 \times 10^{-5}$$
  (Sobrevive a la corrección de Bonferroni $p_{\text{adj}} = 7.0 \times 10^{-5}$ y Benjamini-Hochberg FDR).
- **Aporte Marginal del DOM ($M_1 \to M_2$):**
  $$\Delta F_1 = +0.0063 \quad [\text{IC}_{95\%}: -0.0137, +0.0270], \quad \chi^2 = 0.071, \quad p = 0.7905 \quad (\text{No significativo})$$

### 2.2. Mitigación de Falsos Negativos (Fase 2 y 5)
- De los 25 falsos negativos de la cascada simétrica original ($M_4$), 13 ocurrían antes de $M_2$ por URLs con estructura sintáctica limpia en servicios de confianza (e.g. `delivery-dhlswitzerland.firebaseapp.com`).
- La **Cascada Asimétrica (Política C)**, al exigir $p_0 \le 0.005$ para clasificar como benigno, **recupera 3 de estos ataques complejos** (TP sube de 166 a 169), reduciendo los falsos negativos verificables en predicciones individuales de 25 a 22 y aumentando el Recall de $86.91\%$ a $88.48\%$ ($F_1 = 0.9311$).

### 2.3. Disponibilidad Multimodal y Sesgo de Supervivencia (Fase 3)
- En el sondeo en vivo de $N=600$ URLs (300 phishing, 300 legítimas), la tasa de completitud fue de solo $13.33\%$ en phishing (40/300) frente al $69.00\%$ en legítimos (207/300).
- **Asociación Diferencial de Disponibilidad:** Odds Ratio $= 14.47$, Fisher exacto $p = 4.28 \times 10^{-46}$. Este patrón aporta fuerte evidencia empírica consistente con un comportamiento de datos faltantes no aleatorio (MNAR / sesgo de supervivencia), sin pretender constituir una demostración matemática formal del mecanismo no observado en el sentido estricto de Rubin.
- Evaluar sólo el caso completo ($N=247$) incurre en sesgo de supervivencia, ignorando el $86.7\%$ de los ataques.
- La **Estrategia C (Fallback a $M_0$)** resuelve el 100% de la cohorte $N=600$ con **Precisión = $93.64\%$**, **$\text{FPR} = 5.00\%$** y **$F_1 = 0.8246$**.
- La imputación ingenua con ceros (Estrategia F) dispara el $\text{FPR}$ al **$18.67\%$** (56 sitios benignos bloqueados) y queda categóricamente rechazada.

### 2.4. Rendimiento Temporal y Costes de Sistemas (Fase 4)
- **Cómputo en CPU (Nivel A):** $M_0$ ($14.74 \text{ ms}$), $M_1$ ($29.25 \text{ ms}$), $M_2$ ($44.07 \text{ ms}$), $M_3$ ($58.74 \text{ ms}$).
- **Adquisición de Red e I/O (Nivel B):** DNS ($213.6 \text{ ms}$ P50), HTTP ($981.7 \text{ ms}$ P50), Red total M1 ($1,272.7 \text{ ms}$ P50), Chrome CDP ($2,166.4 \text{ ms}$ P50).
- **Ahorro Temporal Pareado en $N=83$:**
  - Cascada Original vs $M_3$: Ahorro del **$71.81\%$** en tiempo medio ($p = 1.66 \times 10^{-13}$, Wilcoxon).
  - Cascada Original vs $M_2$: Ahorro del **$31.44\%$** en tiempo medio ($p = 0.000159$, Wilcoxon).
  - Cascada Asimétrica vs $M_3$: Ahorro del **$66.09\%$** ($p = 1.15 \times 10^{-14}$, Wilcoxon).
- **Usabilidad en Cliente (Nivel C):** FastAPI `/check` responde en **$19.75 \text{ ms}$** ($P_{90} = 26.46 \text{ ms}$), cumpliendo el umbral de Nielsen (< 100 ms). La extensión actualiza la insignia en **$0.25 \text{ ms}$** con caché caliente y en **$20.00 \text{ ms}$** con caché fría.

---
*Fin del documento de resultados consolidados — Paquete de Transferencia.*
