# RESUMEN CIENTÍFICO DEFINITIVO Y DICTAMEN METODOLÓGICO: RAEA-PHISH

**Título de la Investigación:**  
*Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad*  
*(Automated Detection of Phishing Websites Through Risk- and Availability-Aware Adaptive Evidence Acquisition)*

**Proyecto:** PhishPe / PhishGuard Pro  
**Rama:** `research/risk-aware-policy`  
**Commit:** `2910b6a4495c5068761af40f08efceaf123a4b08`  
**Commit Congelado de Modelos:** `058169a99786a42203d7db27d5da994b6ceb61c9` (`corrections-phase2`)  
**Fecha de Certificación:** 22 de Octubre de 2026  

---

## 1. PROBLEMA DE INVESTIGACIÓN Y OBJETIVOS

### 1.1. Problema
Los sistemas multimodales de detección de phishing web que analizan características léxicas ($M_0$), infraestructura de red DNS/TLS ($M_1$) y contenido HTML/DOM ($M_2$) enfrentan una limitación operacional crítica: adquirir todas las modalidades para cada URL genera latencias inaceptables y consumo excesivo de ancho de banda. Las cascadas adaptativas tradicionales detienen el análisis basándose en umbrales estáticos de confianza o entropía de Shannon, pero presentan tres fallas metodológicas:
1. **Pérdida Simétrica Implícita:** Tratan por igual una falsa alarma que un falso negativo, provocando salidas benignas prematuras en $M_0$ que permiten que sitios de phishing con URLs sintácticamente plausibles evadan la inspección.
2. **Ceguera ante la Disponibilidad:** Asumen disponibilidad del 100%, incurriendo en reintentos y timeouts costosos cuando el servidor DNS o el sitio web están caídos o bloqueados.
3. **Ausencia de Clasificación Selectiva:** Fuerzan una decisión binaria en casos de alta incertidumbre residual donde la evidencia disponible es insuficiente.

### 1.2. Objetivos
Diseñar, implementar y evaluar una política de adquisición adaptativa de evidencia (RAEA-Phish) que optimice de forma conjunta el riesgo asimétrico de clasificación ($\gamma = C_{\text{FN}} / C_{\text{FP}} = 15$), la probabilidad de disponibilidad modal estimada $\hat{\pi}_m(X_0)$ y el coste de adquisición, incorporando una opción de abstención explícita ($C_{\text{abst}} = 0.35$).

---

## 2. CONTRIBUCIÓN CIENTÍFICA REAL Y DELIMITADA

En estricto apego a los principios de honestidad intelectual, la contribución demostrada por la evidencia empírica se delimita de la siguiente manera:

### Lo que RAEA SÍ aporta y demuestra:
1. **Ahorro Comprobado de Coste de Adquisición:** RAEA reduce en un **$37.1\%$** el coste normalizado de adquisición frente a un modelo fijo M1 ($0.2407$ vs $0.3831$, $p = 0.0002$, $p_{\text{Holm}} = 0.0006$), disminuyendo las modalidades consultadas de $2.000$ a $1.576$ mediante cortocircuito inmediato en $M_0$ para URLs manifiestas.
2. **Mitigación de Falsos Negativos Prematuros:** RAEA reduce en un **$70.0\%$ los falsos negativos tempranos en $M_0$** frente a cascadas basadas en entropía de Shannon (B3 comete 10 FN tempranos en phishing web; RAEA comete solo 3).
3. **Toma de Decisiones Consciente de la Disponibilidad:** Desactiva la adquisición de contenido costoso cuando la probabilidad predicha de caída del servidor es alta, alterando selectivamente 43 trayectorias y 14 decisiones frente a la variante sin disponibilidad (A1).

### Lo que RAEA NO aporta (Límites Demostrados):
1. **No supera a M1 en F1 a cobertura forzada total:** En cobertura obligatoria al 100% bajo *Fail-Open*, RAEA obtiene $F1 = 0.8844$ frente a $0.8933$ de M1 (diferencia no significativa, McNemar $p = 1.000$).
2. **No supera en riesgo puro a una regla selectiva de Chow sobre M1 (B5):** Si el sistema dispone de recursos para consultar la infraestructura de red en todas las URLs sin restricción de coste, aplicar la regla selectiva de Chow directamente sobre M1 ($B5\_M1\_chow$) logra un riesgo penalizado menor que RAEA ($0.3657$ vs $0.8390$) con un F1 selectivo de $0.9630$. La ventaja de RAEA se manifiesta exclusivamente cuando existe coste o latencia en el sondeo de red.
3. **La guarda benigna en $M_0$ no tiene beneficio incremental observable:** En presencia de costes asimétricos ($\gamma=15, C_{\text{abst}}=0.35$), la regla Bayes-óptima impone endógenamente $p_0 \le 0.0233$ para salida benigna, haciendo que la guarda heurística ($p_{\text{safe}}=0.0200$) sea redundante sobre esta muestra.

---

## 3. METODOLOGÍA, POBLACIONES EXPERIMENTALES Y COMPARADORES

### 3.1. Esquema de Partición y Prevención de Fuga
- **Cohorte Base:** Cohorte 2 empírica ($N=600$ URLs).
- **Partición de Entrenamiento de Disponibilidad (`train_avail`):** $N = 300$ URLs (150 positivas, 150 negativas).
- **Partición Confirmatoria de Evaluación (`test_eval`):** $N = 300$ URLs (150 positivas, 150 negativas). Ningún hiperparámetro de RAEA fue ajustado sobre esta partición. Solapamiento de dominios entre train y test: **0**.

### 3.2. Poblaciones de Evaluación Auditadas
1. **`PHISHING_WEB_TEST` (POBLACIÓN PRINCIPAL, $N=118$):**
   - **80 sitios web de phishing verificados:** Procedentes de PhishTank (`verified == 'yes'`, 64 URLs) y OpenPhish (16 URLs). Todas corresponden a recursos web interactivos.
   - **38 controles legítimos verificados:** Dominios confirmados por doble consenso en Tranco y Majestic Million, y estrictamente ausentes de los feeds de amenazas.
   - **Exclusión documentada:** 70 URLs de URLhaus identificadas como binarios y scripts de malware puro (`.exe`, `.sh`, `.apk`, `.bin`, `.lnk`, drop sites de botnets) fueron excluidas de la afirmación de phishing web.
   - **112 URLs con etiqueta incierta** (un solo ranking de popularidad sin doble consenso) reservadas para análisis de sensibilidad.
2. **`PHISHING_WEB_TEST_BROAD` (Sensibilidad, $N=230$):** 80 phishing web verificados + 150 controles legítimos ausentes de feeds de amenazas.
3. **`ORIGINAL_TEST_N300` (Histórica, $N=300$):** Partición histórica completa conservada para trazabilidad.

### 3.3. Comparadores Evaluados
- **B0 (M0 Fijo):** Clasificador léxico a umbral 0.50.
- **B1 (M1 Fijo):** Clasificador de infraestructura de red (URL + DNS + TLS) a umbral 0.50.
- **B1_bayes:** M1 con umbral óptimo de Bayes $\tau^* = 1 / (1 + \gamma) = 0.0625$.
- **B2 (M2 Completo):** Clasificador de contenido (URL + Red + HTML/DOM) a umbral 0.50.
- **B3 (Cascada de Entropía):** Cascada heurística basada en entropía de Shannon ($H_{\text{esc}}=0.15, H_{\text{abst}}=0.20$).
- **B4 (Conservadora):** Cascada con bloqueo de salida benigna en $M_0$ salvo $p_0 \le 0.02$.
- **B5_M1_chow:** Política selectiva de Chow sobre M1 (decide si $p_1 \ge 0.9767$ o $p_1 \le 0.0233$; abstiene en caso contrario).
- **B5_M1_cov:** Política selectiva sobre M1 con umbral de confianza ajustado en `train_avail` para igualar la cobertura empírica de RAEA.
- **B6 (RAEA Completo):** Política RAEA con configuración pre-registrada base.

---

## 4. RESULTADOS COMPARATIVOS VERIFICADOS (`PHISHING_WEB_TEST`, $N=118$)

Todas las cifras fueron recalculadas desde [`PREDICCIONES_INDIVIDUALES.csv`](file:///d:/Proyects/Seguridad_Informacion/artifacts/raea_final/PREDICCIONES_INDIVIDUALES.csv). Cero discrepancias matemáticas.

```
Población: PHISHING_WEB_TEST (N=118: 80 Phishing Web Verificado, 38 Legítimo Verificado)
Costes Base: C_FP = 1.0, gamma = 15.0, C_abst = 0.35, lambda = 0.25
```

| Política / Modelo | Cobertura ($\phi$) | Abstención ($N_{\text{abs}}$) | TP Sel | FP Sel | TN Sel | FN Sel | Precision Sel | Recall Sel | F1 Selectivo | F1 Fail-Open | F1 Fail-Closed | Coste Adquisición | Modalidades Medias | Riesgo Penalizado |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **B0: M0 Léxico** | $100.0\%$ | 0 | 46 | 2 | 36 | 34 | 0.9583 | 0.5750 | 0.7188 | 0.7188 | 0.7188 | 0.0000 | 1.000 | 4.3390 |
| **B1: M1 Red** | $100.0\%$ | 0 | 67 | 3 | 35 | 13 | 0.9571 | 0.8375 | 0.8933 | 0.8933 | 0.8933 | 0.3831 | 2.000 | 1.6780 |
| **B1_bayes: M1 Umbral Bayes** | $100.0\%$ | 0 | 75 | 10 | 28 | 5 | 0.8824 | 0.9375 | 0.9091 | 0.9091 | 0.9091 | 0.3831 | 2.000 | 0.7203 |
| **B2: M2 Contenido** | $100.0\%$ | 0 | 70 | 2 | 36 | 10 | 0.9722 | 0.8750 | 0.9211 | 0.9211 | 0.9211 | 1.2983 | 3.000 | 1.2881 |
| **B3: Cascada Entropía** | $84.7\%$ | 18 | 56 | 1 | 33 | 10 | 0.9825 | 0.8485 | 0.9106 | 0.8175 | 0.9032 | 0.5169 | 1.915 | 1.3331 |
| **B4: Conservadora** | $93.2\%$ | 8 | 63 | 1 | 34 | 12 | 0.9844 | 0.8400 | 0.9065 | 0.8750 | 0.8947 | 0.5169 | 1.915 | 1.5576 |
| **B5_M1_chow: Selectiva Chow (M1)** | $75.4\%$ | 29 | 65 | 3 | 19 | **2** | 0.9559 | **0.9701** | **0.9630** | 0.8784 | 0.8814 | 0.3831 | 2.000 | **0.3657** |
| **B5_M1_cov: Cobertura Igualada** | $81.4\%$ | 19 | 60 | 2 | 30 | 7 | 0.9677 | 0.8955 | 0.9302 | 0.8706 | 0.9153 | 0.3831 | 2.000 | 0.9631 |
| **B6: RAEA Completo** | **$83.1\%$** | **20** | **65** | **2** | **25** | **6** | **0.9701** | **0.9155** | **0.9420** | **0.8844** | **0.9186** | **0.2407** | **1.576** | **0.8390** |

> [!IMPORTANT]
> **Reconciliación Exacta de F1:**  
> Para RAEA en `PHISHING_WEB_TEST`, la matriz selectiva es: $TP = 65, FP = 2, TN = 25, FN = 6$ ($N_{\text{dec}} = 98$).  
> $$F1_{\text{sel}} = \frac{2 \times 65}{2 \times 65 + 2 + 6} = \frac{130}{138} = \mathbf{0.9420289855 \approx 0.9420}$$  
> La cifra anterior de 0.9487 fue identificada como un error tipográfico de transcripción y queda formalmente corregida a **0.9420**.

---

## 5. ESTUDIO DE ABLACIÓN VERIFICADO (`PHISHING_WEB_TEST`)

| Variante | Componente Modificado | Cobertura | FN Sel | FP Sel | F1 Selectivo | F1 Fail-Open | Coste Normalizado | Modalidades Solicitadas | Trayectorias Distintas vs A6 |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **A1** | Sin estimador de disponibilidad ($\pi_m=1$) | $83.9\%$ | 3 | 3 | 0.9583 | 0.9079 | 0.3831 | 2.000 | **43** |
| **A2** | Sin costes asimétricos ($\gamma=1$) | $97.5\%$ | 15 | 2 | 0.8794 | 0.8611 | 0.2305 | 1.441 | **25** |
| **A3** | Sin mecanismo de abstención ($C_{\text{abst}}=\infty$) | **$100.0\%$** | 8 | 6 | 0.9114 | 0.9114 | 0.2746 | 1.678 | **20** |
| **A4** | Sin beneficio informativo esperado (VOI) | $58.5\%$ | 10 | 1 | 0.8932 | 0.7244 | **0.0000** | **1.000** | **61** |
| **A5** | Sin guarda benigna en $M_0$ | $83.1\%$ | 6 | 2 | 0.9420 | 0.8844 | 0.2407 | 1.576 | 0 |
| **A6** | **RAEA Completo** | $83.1\%$ | 6 | 2 | 0.9420 | 0.8844 | 0.2407 | 1.576 | 0 |

### Diagnóstico de A5 vs A6:
- La variante A5 desactiva la guarda heurística `enforce_benign_guard=False`.
- Sin embargo, la condición Bayes-óptima para clasificar como benigno en $M_0$ exige que el riesgo de falso negativo sea inferior a la mejor opción terminal: $15.0 \cdot p_0 \le 0.35 \implies p_0 \le 0.0233$.
- Al ser $p_{\text{safe}} = 0.0200$, la función de pérdida asimétrica impone intrínsecamente la misma restricción que la guarda.
- En consecuencia, la guarda no aporta beneficio incremental observable en esta muestra y se cataloga formalmente como un **mecanismo de defensa en profundidad**, evitando presentarla falsamente como una contribución algorítmica independiente.

---

## 6. INFERENCIA ESTADÍSTICA Y PRUEBAS DE HIPÓTESIS

Evaluadas mediante remuestreo Bootstrap pareado por URL ($B=5,000$ iteraciones) con corrección de Holm sobre las 3 hipótesis primarias pre-registradas en `configs/raea_final_experiment.json`:

```
Hipótesis Primarias Pre-Registradas en PHISHING_WEB_TEST (N=118):
```

1. **H3: Reducción de Coste de Adquisición (RAEA vs M1 Fijo):**
   - Estimación media pareada: $\mathbf{-0.1424}$ unidades normalizadas ($-37.1\%$).
   - Intervalo de confianza al 95%: $\mathbf{[-0.2008, -0.0831]}$.
   - $p_{\text{one-sided}} = 0.0002$, **$p_{\text{Holm}} = \mathbf{0.0006}$**.
   - **Veredicto: ACEPTADA CON ALTA SIGNIFICANCIA ($p < 0.001$).** RAEA reduce de forma robusta el consumo de modalidades.

2. **H1: Reducción de Riesgo Ponderado (RAEA vs M1 Fijo):**
   - Estimación media pareada: $-0.8390$ ($0.8390$ vs $1.6780$).
   - Intervalo de confianza al 95%: $[-1.7258, +0.0306]$.
   - $p_{\text{one-sided}} = 0.0294$, **$p_{\text{Holm}} = 0.0588$**.
   - **Veredicto: NO SIGNIFICATIVA AL UMBRAL ESTRICTO DEL 5% TRAS HOLM ($p = 0.0588$).** Existe una tendencia favorable clara a nivel nominal ($p < 0.05$), pero el intervalo de confianza cruza levemente el cero (+0.0306) tras la corrección por comparaciones múltiples.

3. **H2: Reducción de Riesgo frente a Política Selectiva Sencilla (RAEA vs B5_M1_chow):**
   - Estimación media pareada: $+0.4733$ ($0.8390$ vs $0.3657$).
   - Intervalo de confianza al 95%: $[+0.0780, +0.9962]$.
   - $p_{\text{one-sided}} = 0.9836$, **$p_{\text{Holm}} = 0.9836$**.
   - **Veredicto: RECHAZADA DEFINITIVAMENTE.** B5_M1_chow es superior a RAEA en reducción de riesgo ($0.3657$ vs $0.8390$, $p = 0.0332$).

4. **Exactitud Binaria Simétrica (McNemar):**
   - RAEA vs M1 (Fail-Open): RAEA gana 3, M1 gana 4, $p = 1.000$.
   - RAEA vs M1 (Fail-Closed): RAEA gana 11, M1 gana 14, $p = 0.690$.
   - **Veredicto:** En exactitud binaria simétrica forzada al 100%, ambos métodos son estadísticamente indistinguibles.

---

## 7. AMENAZAS A LA VALIDEZ Y LIMITACIONES

1. **Tamaño Muestral de Controles ($N=38$):**  
   Al exigir consenso independiente cruzado en Tranco y Majestic y ausencia de los 3 feeds de amenazas, el conjunto de prueba retuvo 38 controles legítimos confirmados. Cada falso positivo representa un $2.63\%$ en la tasa FPR, limitando la potencia estadística para detectar diferencias finas de falsas alarmas. No obstante, el análisis en la cohorte amplia (`PHISHING_WEB_TEST_BROAD`, $N=230$, con 150 controles) corrobora que la reducción de coste de RAEA se mantiene inalterada ($-35.1\%$, $p < 0.001$).
2. **Naturaleza Replay Offline:**  
   Las probabilidades y estados provienen de los sondeos empíricos reales de la Cohorte 2, pero la trayectoria de RAEA se evaluó mediante un simulador replay determinista, no en una sesión interactiva en navegador en vivo.
3. **Dependencia de la Asimetría de Costes:**  
   Si los costes de clasificación son simétricos ($\gamma = 1.0$), el beneficio de RAEA decae y no se justifica la complejidad frente a un clasificador estático.

---

## 8. DICTAMEN FINAL SOBRE PREPARACIÓN PARA REDACCIÓN DEL ARTÍCULO

**DICTAMEN: FAVORABLE Y METODOLÓGICAMENTE PREPARADO.**

El artículo científico **PUEDE REDACTARSE CON RIGOR Y CREDIBILIDAD**, fundamentándose en las siguientes directrices:
- **Eje de la Contribución:** El manuscrito debe articular a RAEA como una **política de optimización del trade-off entre coste computacional, disponibilidad y riesgo asimétrico**, destacando su ahorro del $37.1\%$ en consultas de red y su capacidad para podar el $70\%$ de los falsos negativos tempranos de cascadas adaptativas.
- **Transparencia en Limitaciones:** Debe reportarse explícitamente que RAEA no supera a M1 en F1 binario completo ni supera a la regla selectiva de Chow si el sondeo de red se asume sin coste.
- **Reproducibilidad:** Todos los resultados provienen de datos auditados, predicciones individuales verificadas y pruebas deterministas automatizadas contenidas en el paquete final [`RAEA_PHISH_EVIDENCIA_PARA_ARTICULO.zip`](file:///d:/Proyects/Seguridad_Informacion/RAEA_PHISH_EVIDENCIA_PARA_ARTICULO.zip).
