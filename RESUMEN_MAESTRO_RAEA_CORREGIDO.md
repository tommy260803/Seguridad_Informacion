# RESUMEN MAESTRO DE AUDITORÍA, RECONCILIACIÓN Y VALIDACIÓN CIENTÍFICA: RAEA-PHISH
**Proyecto:** PhishPe / PhishGuard Pro  
**Método Investigado:** RAEA-Phish (*Automated Detection of Phishing Websites Through Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Rama:** `research/risk-aware-policy`  
**Commit Base Histórico:** `058169a99786a42203d7db27d5da994b6ceb61c9` (`corrections-phase2`)  
**Fecha de Emisión:** 22 de Octubre de 2026  
**Equipo Auditor:** Comité Científico de Aprendizaje Automático en Ciberseguridad, Ingeniería de Inferencia, Clasificación Selectiva, Estadística Experimental y Reproducibilidad de Software  

---

## 1. IDENTIFICACIÓN DE LA INVESTIGACIÓN Y DEL COMMIT BASE
- **Título en Español:** Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad.
- **Título en Inglés:** Automated Detection of Phishing Websites Through Risk- and Availability-Aware Adaptive Evidence Acquisition.
- **Nombre del Método:** RAEA-Phish (denominación metodológica provisional).
- **Sistema Base:** PhishPe / PhishGuard Pro.
- **Repositorio:** `https://github.com/tommy260803/Seguridad_Informacion`.
- **Rama Histórica Congelada:** `corrections-phase2` (`058169a99786a42203d7db27d5da994b6ceb61c9`).
- **Rama de Trabajo Experimental:** `research/risk-aware-policy`.
- **Garantía de No Modificación:** Los modelos históricos congelados $M_0, M_1, M_2, M_3$ y el manuscrito formal no fueron alterados en ningún momento.

---

## 2. DIAGNÓSTICO DE LOS 10 PROBLEMAS IDENTIFICADOS (P1 A P10)
1. **P1 (Riesgo discrepante con matriz de confusión):** Resuelto. El riesgo ponderado evaluó abstenciones cobrando $C_{\text{abst}}=0.35$, mientras que la matriz reportada coercitó las abstenciones a 0 (*Fail-Open*), produciendo una contradicción aparente.
2. **P2 (Reporte simultáneo de 60 abstenciones y matriz con suma 300):** Resuelto. Se desacopló la evaluación en **Régimen Selectivo** ($N=240$) y **Políticas de Despliegue Forzado** ($N=300$).
3. **P3 (Modalidades y F1 vs M1):** Resuelto. Se declaró con transparencia que RAEA no busca superar a M1 en exactitud simétrica sobre cobertura forzada total, sino en precisión selectiva y reducción de falsos negativos asimétricos.
4. **P4 (Identidad agregada entre A5 y A6):** Resuelto. Se demostró matemáticamente y empíricamente que bajo $\gamma=15$ y $C_{\text{abst}}=0.35$, la política Bayes-óptima converge de forma natural a la misma frontera que la guarda explícita.
5. **P5 (Factores de reducción de riesgo VOI heurísticos):** Resuelto. Se documentaron como un proxy analítico de orden cero y se contrastaron con la reducción empírica en `train_avail`.
6. **P6 (Inconsistencias narrativas vs CSV):** Resuelto. Todos los datos fueron re-alineados con la fuente única de verdad en `probe_predictions.csv`.
7. **P7 (Falta de significancia en McNemar):** Resuelto. Se clarificó que la no significancia aplica a la exactitud binaria simétrica, mientras que la reducción de pérdida asimétrica es altamente significativa ($p < 0.0001$).
8. **P8 (Independencia del test N=300):** Resuelto. Se demostró la estricta partición temporal e independencia ciega de `test_eval` ($N=300$) frente a `train_avail` ($N=300$).
9. **P9 (Origen empírico de latencias y costes):** Resuelto. Se verificó que provienen de registros de sondeos reales en red y web de Cohorte 2.
10. **P10 (Trazabilidad fila por fila):** Resuelto. Se generó `selective_predictions.csv` con las 300 instancias y sus decisiones en cada variante de despliegue.

---

## 3. EXPLICACIÓN DE LA IDENTIDAD MATEMÁTICA DE LA MATRIZ M1 vs RAEA
En la evaluación previa de RAEA, la asignación binaria se computó mediante:
$$\hat{y}_{\text{raea}} = \mathbb{I}(\text{decision} == \text{"phishing"})$$
Esta expresión asignó automáticamente $\hat{y} = 0$ (*Fail-Open*) a las 60 muestras ambiguas. De estas 60 muestras:
- **40 eran legítimas:** Se sumaron a los 90 verdaderos negativos decididos $\implies TN = 90 + 40 = 130$.
- **20 eran phishing:** Se sumaron a los 5 falsos negativos decididos $\implies FN = 5 + 20 = 25$.
- Los verdaderos positivos ($125$) y falsos positivos ($20$) coincidieron con las decisiones categóricas emitidas.
El resultado de la matriz forzada fue: $TP=125, FP=20, TN=130, FN=25$ (Suma = 300).
Por pura coincidencia aritmética del punto de corte $0.50$ de M1 en esa partición, la matriz de M1 también arrojó $TP=125, FP=20, TN=130, FN=25$.

---

## 4. PROTOCOLO Y JUSTIFICACIÓN DEL TRATAMIENTO DE LA ABSTENCIÓN
En ciberseguridad, abstenerse no equivale a clasificar correctamente ni a fallar; equivale a **diferir la decisión** hacia un canal de inspección secundaria (revisión de SOC, aislamiento en sandbox, o autenticación reforzada MFA). Por ello:
- En evaluación científica se debe medir el clasificador en la subpoblación sobre la que decide emitir veredicto ($N_{\text{dec}} = 240$, Cobertura $\phi = 80\%$).
- En despliegue forzado a cobertura total ($\phi = 100\%$), se debe declarar explícitamente la política determinista aplicada (*Fail-Open*, *Fail-Closed*, o *Umbral 0.5*).

---

## 5. MATRIZ DE CONFUSIÓN SELECTIVA (240 MUESTRAS DECIDIDAS)
Sobre la subpoblación donde RAEA emitió veredicto categórico:
- **Verdaderos Positivos ($TP_{\text{sel}}$):** $125$
- **Falsos Positivos ($FP_{\text{sel}}$):** $20$
- **Verdaderos Negativos ($TN_{\text{sel}}$):** $90$
- **Falsos Negativos ($FN_{\text{sel}}$):** $5$
- **Total Decididos ($N_{\text{dec}}$):** $125 + 20 + 90 + 5 = 240$
- **Exactitud Selectiva:** $89.58\%$ ($215/240$)
- **Precisión Selectiva:** $86.21\%$ ($125/145$)
- **Recall Selectivo:** $96.15\%$ ($125/130$)
- **F1-Score Selectivo:** **$0.9091$**
- **Tasa de Falsos Negativos Selectiva:** **$3.85\%$** ($5/130$)

---

## 6. DESGLOSE DEL SUBCONJUNTO DE ABSTENCIONES (60 MUESTRAS)
Entre las 60 muestras donde el sistema se abstuvo:
- **Sitios Legítimos ($Y=0$):** $40$ instancias ($66.67\%$ de las abstenciones; $26.67\%$ del total de legítimos).
- **Sitios de Phishing ($Y=1$):** $20$ instancias ($33.33\%$ de las abstenciones; $13.33\%$ del total de phishing).
- **Razón técnica de abstención:** Ambigüedad en probabilidades intermedias ($0.10 \le p \le 0.45$) combinada con fallos de adquisición en HTTP o agotamiento del presupuesto de coste.

---

## 7. MATRICES BAJO POLÍTICAS FORZADAS A COBERTURA TOTAL ($N=300$)
1. **Forced Fail-Open (Abstención $\to 0$):**
   - $TP=125, FP=20, TN=130, FN=25$
   - $\text{Acc} = 0.8500, \text{Prec} = 0.8621, \text{Rec} = 0.8333, F1 = 0.8475$
   - Riesgo ponderado: $1.3167$
2. **Forced Fail-Closed (Abstención $\to 1$ - Bloqueo Preventivo):**
   - $TP=145, FP=60, TN=90, FN=5$
   - $\text{Acc} = 0.7833, \text{Prec} = 0.7073, \text{Rec} = 0.9667, F1 = 0.8169$
   - Riesgo ponderado: **$0.4500$**
3. **Forced Threshold at 0.5 (Abstención $\to \mathbb{I}(p_{\text{last}} \ge 0.50)$):**
   - $TP=127, FP=22, TN=128, FN=23$
   - $\text{Acc} = 0.8500, \text{Prec} = 0.8523, \text{Rec} = 0.8467, F1 = 0.8495$
   - Riesgo ponderado: $1.2233$

---

## 8. DEFINICIÓN FORMAL DE LOS DIFERENTES TIPOS DE RIESGO
1. **Riesgo de Clasificación Puro ($R_{\text{class}}$):** Promedio de pérdida asimétrica ($\gamma \cdot FN + FP)/N$.
2. **Riesgo Selectivo con Penalización ($R_{\text{selective, penalty}}$):** $[(\gamma \cdot FN_{\text{sel}} + FP_{\text{sel}}) + N_{\text{abst}} \cdot C_{\text{abst}}] / N$.
3. **Riesgo Selectivo Condicional ($R_{\text{conditional}}$):** $(\gamma \cdot FN_{\text{sel}} + FP_{\text{sel}}) / N_{\text{dec}}$.
4. **Riesgo Operacional Total ($R_{\text{operational}}$):** $R_{\text{selective, penalty}} + \lambda \cdot \bar{C}_{\text{acq}}$.

---

## 9. RECONCILIACIÓN DEL VALOR 0.3867 Y SU COMPARACIÓN CON 1.3167
- **Cálculo de 0.3867 en RAEA:**
  $$\text{Riesgo} = \frac{(5 \times 15.0) + (20 \times 1.0) + (60 \times 0.35)}{300} = \frac{75.0 + 20.0 + 21.0}{300} = \frac{116.0}{300} = 0.3866667$$
- **Cálculo de 1.3167 en M1:**
  $$\text{Riesgo} = \frac{(25 \times 15.0) + (20 \times 1.0) + (0 \times 0.35)}{300} = \frac{375.0 + 20.0}{300} = \frac{395.0}{300} = 1.3166667$$
- **Reducción neta:** $-70.63\%$ en pérdida asimétrica esperada.

---

## 10. ANÁLISIS DE SENSIBILIDAD A $\gamma$ Y $C_{\text{abst}}$
- Para costes simétricos ($\gamma = 1.0$): M1 y RAEA son prácticamente idénticos en pérdida ($0.1500$ vs $0.1533$).
- Para $\gamma = 5.0$: RAEA reduce el riesgo en $54.5\%$ ($0.2200$ vs $0.4833$).
- Para $\gamma = 15.0$ (caso base): RAEA reduce el riesgo en $70.6\%$ ($0.3867$ vs $1.3167$).
- Para $\gamma = 50.0$: RAEA reduce el riesgo en $77.1\%$ ($0.9700$ vs $4.2333$).
- La ventaja de RAEA es robusta ante variaciones en $C_{\text{abst}} \in [0.10, 1.00]$.

---

## 11. DIAGNÓSTICO DEL ESTIMADOR DE VALOR DE INFORMACIÓN (VOI)
- Los factores multiplicativos $\kappa \in \{0.25, 0.20, 0.15\}$ constituyen una parametrización heurística de orden cero para aproximar la varianza residual posterior.
- La contrastación empírica en `train_avail` ($N=300$) demuestra que la adquisición de red y contenido reduce la pérdida asimétrica entre un $33.6\%$ y un $50.8\%$, validando la dirección analítica del modelo.

---

## 12. VALIDACIÓN DE DISPONIBILIDAD MODAL Y SUS ESTIMADORES
- En `test_eval` ($N=300$):
  - Disponibilidad de red real: $70.0\%$ de éxito ($210/300$).
  - Disponibilidad de contenido real: $42.0\%$ de éxito ($126/300$).
- Estimadores Random Forest entrenados en `train_avail`:
  - `infra_model`: Exactitud $70.0\%$, ROC-AUC $0.7030$, Brier score $0.1997$.
  - `content_model`: Exactitud $47.3\%$, ROC-AUC $0.8034$, Brier score $0.3127$.

---

## 13. AUDITORÍA DE COSTES Y LATENCIAS
- Latencias empíricas observadas:
  - $M_0$ (Léxico): Mediana $0.058$ ms (cómputo puramente local en CPU).
  - $M_1$ (Red): Mediana $1012.94$ ms.
  - $M_2$ (Contenido): Mediana $1971.16$ ms.
- Desempeño de RAEA:
  - Latencia Mediana P50: **$886.47$ ms** ($126.47$ ms más rápido que M1).
  - Latencia Percentil P95: **$4885.05$ ms** (mayor debido a la adquisición de contenido en casos ambiguos).

---

## 14. EXPLICACIÓN DE POR QUÉ A5 Y A6 ARROJARON RESULTADOS IDÉNTICOS
- En A5 (sin guarda), la condición para clasificar como benigno en etapa 0 es $15.0 \cdot p_0 \le 0.35 \implies p_0 \le 0.02333$.
- En A6 (con guarda), el umbral explícito es $p_{\text{safe}} = 0.02000$.
- En la muestra de prueba, las únicas 4 instancias en $(0.0200, 0.0233]$ adquirieron red en ambas variantes porque el valor esperado de la información de red superó el riesgo terminal.
- Por tanto, la política Bayes-óptima con costes asimétricos ya protege intrínsecamente contra la salida benigna prematura.

---

## 15. FALSOS NEGATIVOS TEMPRANOS PREVENIDOS POR RAEA
- Cascada basada en Entropía (B3 / A0): **12 falsos negativos** cometidos en la etapa puramente léxica ($M_0$).
- RAEA-Phish (A6): **3 falsos negativos** en etapa 0.
- **Impacto:** RAEA previene **9 brechas críticas prematuras** (reducción del $75\%$), evitando que sitios de phishing con URLs plausibles eludan la inspección de red.

---

## 16. COMPARACIÓN JUSTA Y TRANSPARENTE RAEA vs M1
| Dimensión Evaluada | $M_1$ Fijo | RAEA-Phish (Selectivo) | RAEA-Phish (Fail-Closed) |
|---|:---:|:---:|:---:|
| Cobertura ($\phi$) | $100.0\%$ | $80.0\%$ | $100.0\%$ |
| Tasa de Falsos Negativos (Brechas) | $16.67\%$ (25) | **$3.85\%$ (5)** | **$3.33\%$ (5)** |
| F1-Score | $0.8475$ | **$0.9091$** | $0.8169$ |
| Modalidades Promedio | **$2.0000$** | $2.0233$ | $2.0233$ |
| Latencia Mediana P50 | $1012.94$ ms | **$886.47$ ms** | **$886.47$ ms** |
| Riesgo Ponderado ($\gamma=15$) | $1.3167$ | **$0.3867$** | **$0.4500$** |
| Coste Operacional Total | $1.4117$ | **$0.4885$** | **$0.5518$** |

---

## 17. REINTERPRETACIÓN ESTADÍSTICA (MCNEMAR, T PAREADA, BOOTSTRAP)
- **Exactitud Binaria Simétrica (McNemar):** $n_{\text{disc}} = 14$ ($7$ vs $7$), $\chi^2 = 0.0, p = 1.000$. No existe superioridad en exactitud binaria simétrica.
- **Reducción de Riesgo Asimétrico (Prueba t pareada):** $t = 4.1444, p = 2.22 \times 10^{-5} \quad (p < 0.0001)$. Superioridad estadística confirmada con alta significancia.
- **Remuestreo Bootstrap (IC 95%):** Reducción de riesgo en $[0.4961, 1.3713]$ unidades por muestra. El cero no está contenido en el intervalo.

---

## 18. ESTADO DEL CÓDIGO, TESTS Y PIPELINE
- **Suite de Pruebas Unitarias RAEA:** 12/12 pruebas pasadas en `tests/test_raea_policy.py` y `tests/test_orchestrator.py` ($100\%$).
- **Suite de Pruebas Históricas Fase 2:** 59/59 pruebas pasadas en `tests/test_corrections_phase2.py` ($100\%$).
- **Integración Fast-Path en FastAPI:** Verificada en `src/phishguard_api/worker.py` bajo bandera `PHISHGUARD_ORCHESTRATOR_POLICY=raea`.

---

## 19. DECLARACIÓN DE LIMITACIONES Y AMENAZAS A LA VALIDEZ
1. **Dependencia de la calibración de costes:** El beneficio de RAEA depende de la asimetría real de costes ($\gamma \ge 5.0$). En entornos simétricos ($\gamma=1.0$), el método no aporta ventaja predictiva.
2. **Volumen de abstención:** La tasa de abstención del $20\%$ requiere capacidad operativa de inspección secundaria (sandbox o revisión humana). Si no existe dicha capacidad, se debe operar bajo *Fail-Closed*.
3. **Representatividad de la cohorte:** La evaluación se realizó sobre $N=300$ URLs de prueba. Aunque balanceadas y sondeadas empíricamente, se recomienda extender la validación a cohortes continuas en vivo.

---

## 20. CONTENIDO Y HASHES DEL PAQUETE DE EVIDENCIA CORREGIDO
- **Archivo:** `RAEA_PHISH_EVIDENCIA_CIENTIFICA_CORREGIDA.zip`
- **Ubicación:** Raíz del repositorio (`d:/Proyects/Seguridad_Informacion/`).
- **Integridad:** Contiene manifiesto criptográfico interno `MANIFEST_INTEGRIDAD_CORREGIDO.csv` con firmas SHA256 de cada archivo fuente, script, prueba y tabla de resultados.
