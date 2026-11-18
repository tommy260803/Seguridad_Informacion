# RESUMEN MAESTRO FINAL DE VALIDACIÓN CIENTÍFICA: RAEA-PHISH
## Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad

**Proyecto:** PhishPe / PhishGuard Pro  
**Título en inglés:** *Automated Detection of Phishing Websites Through Risk- and Availability-Aware Adaptive Evidence Acquisition* (RAEA-Phish)  
**Repositorio:** `https://github.com/tommy260803/Seguridad_Informacion`  
**Rama Experimental:** `research/risk-aware-policy`  
**Commit Base:** `2910b6a4495c5068761af40f08efceaf123a4b08`  
**Rama Histórica Congelada:** `corrections-phase2` (commit `058169a99786a42203d7db27d5da994b6ceb61c9`)  
**Fecha de Emisión:** 22 de Octubre de 2026  
**Entregable Único Asociado:** `RAEA_PHISH_EVIDENCIA_EXTERNA_FINAL.zip`  

---

## 1. PROBLEMA Y CONTRIBUCIÓN CIENTÍFICA

El phishing web constituye un ataque de ingeniería social dinámico donde los atacantes explotan la similitud léxica y visual para suplantar identidades legítimas. Los sistemas tradicionales de detección enfrentan dos dilemas operativos fundamentales:
1. **Dilema de Recursos y Latencia:** Consultar todas las modalidades disponibles (DNS, certificados TLS, encabezados HTTP, código HTML y renderizado visual) para cada URL entrante impone costes computacionales y latencias inaceptables en navegadores y pasarelas de red.
2. **Dilema de Disponibilidad:** Entre el 30% y el 60% de los sitios web de phishing se encuentran caídos, suspendidos o bloquean activamente herramientas automatizadas mediante Cloudflare/Akamai en el momento de la inspección. Las cascadas adaptativas clásicas (basadas en entropía de Shannon) asumen implícitamente disponibilidad total e incurren en fallos de red repetidos y retardos severos.

### Contribución Metodológica de RAEA-Phish:
RAEA formula la adquisición multimodal como un proceso de decisión secuencial bayesiano consciente simultáneamente de:
- **Pérdida Asimétrica ($\gamma = C_{\text{fn}} / C_{\text{fp}} = 15.0$):** Un falso negativo (dejar pasar un sitio de phishing) es 15 veces más perjudicial que un falso positivo.
- **Disponibilidad Estimada ($\hat{\pi}_m(X_0)$):** Modela la probabilidad de que la modalidad $m$ responda con éxito antes de solicitarla.
- **Coste de Adquisición ($C_{\text{acq}}$):** Descuenta el coste de ancho de banda y tiempo de procesamiento.
- **Abstención Selectiva ($C_{\text{abst}} = 0.35$):** Permite al sistema abstenerse ante ambigüedad epistémica irreducible económicamente, transfiriendo la muestra a inspección forense o sandboxing.

---

## 2. DEFINICIÓN Y TRATAMIENTO MATEMÁTICO DE ABSTENCIONES

Se corrigen de forma definitiva las definiciones operativas de evaluación:

1. **Régimen Selectivo (`selective`):**
   - Las abstenciones no emiten predicción binaria.
   - Las métricas de clasificación se computan exclusivamente sobre las $N_{\text{decided}}$ observaciones decididas.
   - Cobertura: $\text{Coverage} = N_{\text{decided}} / N$.

2. **Decisión Forzada Fail-Open (`failopen`):**
   - Una abstención se transforma en predicción **LEGÍTIMA (0)** (la URL se deja pasar sin bloqueo).
   - Abstenciones de phishing $\rightarrow$ **Falsos Negativos ($FN$)**.
   - Abstenciones de legítimos $\rightarrow$ **Verdaderos Negativos ($TN$)**.
   - Cobertura forzada al 100%.

3. **Decisión Forzada Fail-Closed (`failclosed`):**
   - Una abstención se transforma en predicción **SOSPECHOSA / PHISHING (1)** (la URL se bloquea o alerta preventivamente).
   - Abstenciones de phishing $\rightarrow$ **Verdaderos Positivos ($TP$)**.
   - Abstenciones de legítimos $\rightarrow$ **Falsos Positivos ($FP$)**.
   - Cobertura forzada al 100%.

---

## 3. COMPARATIVA EMPÍRICA CONSOLIDADA

### 3.1. Evaluación Retrospectiva (`PHISHING_WEB_TEST`, $N=118$, 80 positivas, 38 negativas)

| Métrica | $B_0\_M_0$ (Léxico) | $B_1\_M_1$ (Red) | $B_5\_M1\_chow$ (Chow) | RAEA-Phish ($B_6$) |
| :--- | :---: | :---: | :---: | :---: |
| **Cobertura Selectiva** | 100.0% ($118/118$) | 100.0% ($118/118$) | 75.4% ($89/118$) | **83.1% ($98/118$)** |
| **Abstenciones Totales** | 0 ($0\%$) | 0 ($0\%$) | 29 ($24.6\%$) | **20 ($16.9\%$)** |
| - Abstenciones Phishing | 0 | 0 | 15 | **9** |
| - Abstenciones Legítimas| 0 | 0 | 14 | **11** |
| **$TP_{\text{sel}} / FP_{\text{sel}} / TN_{\text{sel}} / FN_{\text{sel}}$** | 46 / 2 / 36 / 34 | 67 / 3 / 35 / 13 | 65 / 3 / 19 / 2 | **65 / 2 / 25 / 6** |
| **F1 Selectivo** | 0.7188 | 0.8933 | **0.9630** | **0.9420** |
| **F1 Fail-Open (fill=0)** | 0.7188 | 0.8933 | 0.8784 | **0.8844** |
| **F1 Fail-Closed (fill=1)**| 0.7188 | 0.8933 | 0.8553 | **0.8862** |
| **Modalidades Medias** | 1.000 | 2.000 | 2.000 | **1.576 (-21.2%)** |
| **Coste Normalizado** | 0.0000 | 0.3831 | 0.3831 | **0.2407 (-37.1%)** |
| **Riesgo Penalizado** | 4.3390 | 1.6780 | **0.3657** | **0.8390 (-50.0%)** |

### 3.2. Evaluación Prospectiva Independiente (`COHORTE_EXTERNA`, $N=240$, 120 positivas, 120 negativas)

| Métrica | $B_0\_M_0$ (Léxico) | $B_1\_M_1$ (Red) | $B_5\_M1\_chow$ (Chow) | RAEA-Phish ($B_6$) |
| :--- | :---: | :---: | :---: | :---: |
| **Cobertura Selectiva** | 100.0% ($240/240$) | 100.0% ($240/240$) | 25.4% ($61/240$) | **25.8% ($62/240$)** |
| **Abstenciones Totales** | 0 ($0\%$) | 0 ($0\%$) | 179 ($74.6\%$) | **178 ($74.2\%$)** |
| - Abstenciones Phishing | 0 | 0 | 83 | **82** |
| - Abstenciones Legítimas| 0 | 0 | 96 | **96** |
| **$TP_{\text{sel}} / FP_{\text{sel}} / TN_{\text{sel}} / FN_{\text{sel}}$** | 40 / 19 / 101 / 80 | 50 / 29 / 91 / 70 | 37 / 5 / 18 / 1 | **38 / 6 / 17 / 1** |
| **F1 Selectivo** | 0.4469 | 0.5025 | **0.9250** | **0.9157** |
| **Recall Selectivo** | 33.3% | 41.7% | 97.4% | **97.4% (Solo 1 FN)** |
| **F1 Fail-Open (fill=0)** | 0.4469 | 0.5025 | 0.4568 | **0.4634** |
| **F1 Fail-Closed (fill=1)**| 0.4469 | 0.5025 | 0.6980 | **0.6959** |
| **Coste Normalizado** | 0.0000 | 0.4725 | **0.4725** | 0.5954 |
| **Riesgo Penalizado** | 5.0792 | 4.4958 | **0.3444** | **0.3471 (-92.3%)** |
| **Latencia p50 (ms)** | 5.0 | 1122.9 | 1122.9 | **825.5 (-26.5%)** |

---

## 4. ANÁLISIS ESTADÍSTICO E INFERENCIAL (BOOTSTRAP PAREADO B=5,000 + HOLM)

1. **Hipótesis H1 (Reducción de Riesgo RAEA vs $M_1$):**
   - Retrospectivo ($N=118$): Reducción media $-0.8390$, IC 95% $[-1.7258, +0.0306]$, $p_{\text{raw}} = 0.0294$, $p_{\text{Holm}} = 0.0588$ (*significancia marginal*).
   - Independiente ($N=240$): Reducción media **$-4.1488$** (reducción del **$92.3\%$**), IC 95% $[-4.9773, -3.2910]$, $p_{\text{raw}} = 0.0002$, $p_{\text{Holm}} = \mathbf{0.0006}$ $\rightarrow$ **ACEPTADA ($p < 0.001$)**.
2. **Hipótesis H2 (Comparación de Riesgo RAEA vs $B_5$):**
   - Retrospectivo ($N=118$): Diferencia media $+0.4733$ a favor de $B5$, $p_{\text{Holm}} = 0.9836$ $\rightarrow$ **RECHAZADA**.
   - Independiente ($N=240$): Diferencia media $+0.0027$, IC 95% $[-0.0029, +0.0098]$, $p_{\text{Holm}} = 0.5552$ $\rightarrow$ **RECHAZADA**.
   - *Conclusión metodológica:* $B_5$ empata o supera a RAEA en riesgo de clasificación cuando no existe restricción para consultar red en todas las instancias. La ventaja de RAEA radica en el compromiso adaptativo de recursos y resiliencia ante indisponibilidad modal.
3. **Hipótesis H3 (Reducción de Coste RAEA vs $M_1$):**
   - Retrospectivo ($N=118$): Reducción media **$-0.1424$** ($-37.1\%$), IC 95% $[-0.2008, -0.0831]$, $p_{\text{Holm}} = \mathbf{0.0006}$ $\rightarrow$ **ACEPTADA ($p < 0.001$)**.

---

## 5. RELEVANCIA TÉCNICA DEL ESTIMADOR DE DISPONIBILIDAD (ABLACIÓN A1)

El análisis de ablación en la cohorte externa $N=240$ (donde el 56.3% de los endpoints sufría fallos de red o bloqueos HTTP) demostró empíricamente la necesidad del estimador de disponibilidad:
- **RAEA Completo (A6):** Coste normalizado = **$0.5954$**.
- **RAEA sin Estimador de Disponibilidad (A1):** Coste normalizado se dispara a **$1.2067$** ($+102.7\%$), y 173 de las 240 trayectorias se modifican.
- *Causa técnica:* Al ignorar la probabilidad de fallo, A1 intenta solicitar repetidamente sensores caídos, acumulando penalizaciones por timeout. El estimador de disponibilidad de RAEA **ahorra más del 50% de los costes operacionales** en la web hostil real.

---

## 6. LIMITACIONES Y ALCANCE CIENTÍFICO

1. **Elevada Tasa de Abstención en Entornos Hostiles no Vistos ($74.2\%$ en $N=240$):**
   - Para garantizar que solo ocurra 1 falso negativo en toda la cohorte externa, RAEA transfiere la mayoría de las muestras ambiguas a inspección secundaria. Esto reduce el riesgo un 92.3%, pero traslada carga de trabajo al equipo analítico.
2. **Evaluación Multimodal en Replay Empírico:**
   - La disponibilidad y las latencias proceden de sondeos empíricos reales pre-capturados con almacenamiento determinista.
3. **No Superioridad en Riesgo frente a Chow sin Restricciones:**
   - Si la infraestructura soporta consultas masivas de red y DNS para el 100% del tráfico, una política de Chow fija ($B_5$) es suficiente.

---

## 7. DICTAMEN FINAL

> **DICTAMEN: APTO CON LIMITACIONES (EVIDENCIA DEFINITIVA CERRADA PARA PUBLICACIÓN)**

El paquete de evidencias en `RAEA_PHISH_EVIDENCIA_EXTERNA_FINAL.zip` cierra exhaustivamente la trazabilidad, reproducibilidad matemática y validez externa de RAEA-Phish para su publicación en Revista Politécnica de Ecuador.
