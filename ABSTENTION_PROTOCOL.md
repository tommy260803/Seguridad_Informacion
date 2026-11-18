# PROTOCOLO DE EVALUACIÓN METODOLÓGICA DE LA ABSTENCIÓN
**Proyecto:** PhishPe / RAEA-Phish  
**Disciplina:** Clasificación Selectiva (*Selective Classification* / *Learning to Reject*)  
**Autor:** Comité de Auditoría y Desarrollo Científico  

---

## 1. FORMULACIÓN MATEMÁTICA DE LA CLASIFICACIÓN SELECTIVA

En un entorno de clasificación selectiva, el sistema predictor se define como una pareja $(f, g)$, donde:
- $f: \mathcal{X} \to \{0, 1\}$ es la función de predicción base (0 = Legítimo, 1 = Phishing).
- $g: \mathcal{X} \to \{0, 1\}$ es la función de selección o admisión ($g(x) = 1$ indica aceptación / decisión emitida; $g(x) = 0$ indica rechazo / abstención).

### 1.1. Población Total y Descomposición Muestral
Para una muestra de evaluación de tamaño total $N = 300$:
$$N = N_{\text{dec}} + N_{\text{abst}}$$

Donde:
- $N_{\text{dec}} = \sum_{i=1}^N g(x_i)$ es el número de instancias donde el clasificador emitió una decisión categórica (*Decided Population*).
- $N_{\text{abst}} = \sum_{i=1}^N (1 - g(x_i))$ es el número de instancias donde el clasificador se abstuvo (*Abstained Population*).

### 1.2. Cobertura Operacional (*Coverage*)
La cobertura $\phi \in [0, 1]$ cuantifica la proporción de transacciones resueltas de forma autónoma:
$$\phi = \frac{N_{\text{dec}}}{N} = 1 - \frac{N_{\text{abst}}}{N}$$

Para RAEA-Phish sobre la partición confirmatoria de prueba ($N=300$):
- $N_{\text{abst}} = 60 \implies \text{Tasa de Abstención} = 20.0\%$
- $N_{\text{dec}} = 240 \implies \text{Cobertura} \phi = 80.0\%$

---

## 2. RÉGIMEN SELECTIVO (*SELECTIVE CLASSIFICATION*)

En el régimen selectivo estricto, la evaluación del clasificador se realiza **exclusivamente sobre la población decidida** ($N_{\text{dec}}$).

### 2.1. Matriz de Confusión Selectiva
Para las instancias con $g(x_i) = 1$:
$$N_{\text{dec}} = TP_{\text{sel}} + FP_{\text{sel}} + TN_{\text{sel}} + FN_{\text{sel}}$$

Sobre el subconjunto de $N_{\text{dec}} = 240$ casos evaluados:
- **Verdaderos Positivos Selectivos ($TP_{\text{sel}}$):** $125$
- **Falsos Positivos Selectivos ($FP_{\text{sel}}$):** $20$
- **Verdaderos Negativos Selectivos ($TN_{\text{sel}}$):** $90$
- **Falsos Negativos Selectivos ($FN_{\text{sel}}$):** $5$

Comprobación aritmética de consistencia:
$$125 + 20 + 90 + 5 = 240 = N_{\text{dec}}$$

### 2.2. Métricas Selectivas
- **Exactitud Selectiva:**
  $$\text{Acc}_{\text{sel}} = \frac{TP_{\text{sel}} + TN_{\text{sel}}}{N_{\text{dec}}} = \frac{125 + 90}{240} = \frac{215}{240} \approx 0.8958 \quad (89.58\%)$$
- **Precisión Selectiva:**
  $$\text{Prec}_{\text{sel}} = \frac{TP_{\text{sel}}}{TP_{\text{sel}} + FP_{\text{sel}}} = \frac{125}{125 + 20} = \frac{125}{145} \approx 0.8621 \quad (86.21\%)$$
- **Exhaustividad / Recall Selectivo:**
  $$\text{Rec}_{\text{sel}} = \frac{TP_{\text{sel}}}{TP_{\text{sel}} + FN_{\text{sel}}} = \frac{125}{125 + 5} = \frac{125}{130} \approx 0.9615 \quad (96.15\%)$$
- **F1-Score Selectivo:**
  $$F1_{\text{sel}} = 2 \cdot \frac{\text{Prec}_{\text{sel}} \cdot \text{Rec}_{\text{sel}}}{\text{Prec}_{\text{sel}} + \text{Rec}_{\text{sel}}} \approx 0.9091 \quad (90.91\%)$$
- **Tasa de Falsos Negativos Selectiva:**
  $$FNR_{\text{sel}} = \frac{FN_{\text{sel}}}{TP_{\text{sel}} + FN_{\text{sel}}} = \frac{5}{130} \approx 0.0385 \quad (3.85\%)$$

> [!IMPORTANT]
> Obsérvese que en el régimen selectivo, RAEA reduce la tasa de falsos negativos del $16.67\%$ (en M1 estático) al **$3.85\%$**, reteniendo solo 5 falsos negativos sobre 130 muestras positivas decididas.

---

## 3. DESGLOSE DEL SUBCONJUNTO EN ABSTENCIÓN

Las $N_{\text{abst}} = 60$ instancias en las que RAEA se abstiene se distribuyen empíricamente de la siguiente manera respecto a su etiqueta real de referencia:
- **Sitios Legítimos en Abstención ($Y = 0$):** $40$ instancias ($66.7\%$ de las abstenciones).
- **Sitios de Phishing en Abstención ($Y = 1$):** $20$ instancias ($33.3\%$ de las abstenciones).

La mayor concentración de abstenciones en sitios legítimos responde a dominios con infraestructura anómala o bloqueos de red que generaron ambigüedad en los clasificadores tempranos.

---

## 4. POLÍTICAS DE DESPLIEGUE FORZADO A COBERTURA TOTAL ($\phi = 100\%$)

En escenarios de producción donde la abstención no puede ser transferida a revisión humana ni a un sistema secundario, se deben definir políticas forzadas deterministas:

### Política 1: *Fail-Open* (Asignación Forzada a Legítimo, $\hat{y}_{\text{abst}} = 0$)
- Las 60 abstenciones se fuerzan a la clase Benigna ($0$).
- Las 40 legítimas se convierten en $TN$ adicionales: $TN = 90 + 40 = 130$.
- Las 20 de phishing se convierten en $FN$ adicionales: $FN = 5 + 20 = 25$.
- **Matriz resultante:** $TP=125, FP=20, TN=130, FN=25$ (Suma = 300).
- **Métricas:** $\text{Acc} = 0.8500, \text{Prec} = 0.8621, \text{Rec} = 0.8333, F1 = 0.8475$.

> [!NOTE]
> Esta política explica exactamente por qué el código anterior arrojó una matriz idéntica a M1: el código coercitaba por defecto `decision == "phishing" ? 1 : 0`, implementando de forma implícita una política *Fail-Open*.

### Política 2: *Fail-Closed* (Asignación Forzada a Phishing / Bloqueo Preventivo, $\hat{y}_{\text{abst}} = 1$)
- Las 60 abstenciones se fuerzan a la clase Maliciosa ($1$).
- Las 20 de phishing se convierten en $TP$ adicionales: $TP = 125 + 20 = 145$.
- Las 40 legítimas se convierten en $FP$ adicionales: $FP = 20 + 40 = 60$.
- **Matriz resultante:** $TP=145, FP=60, TN=90, FN=5$ (Suma = 300).
- **Métricas:** $\text{Acc} = 0.7833, \text{Prec} = 0.7073, \text{Rec} = 0.9667, F1 = 0.8169$.

### Política 3: *Last-Stage Probability Thresholding* ($\hat{y}_{\text{abst}} = \mathbb{I}(p_{\text{last}} \ge 0.50)$)
- En lugar de una asignación constante, se utiliza la probabilidad posterior acumulada en la última modalidad observada antes del límite presupuestario.
- Entre las 60 abstenciones, la distribución de $p_{\text{last}} \ge 0.50$ clasifica:
  - Legítimos: 38 a benigno ($TN$), 2 a phishing ($FP$).
  - Phishing: 18 a benigno ($FN$), 2 a phishing ($TP$).
- **Matriz resultante:**
  - $TP = 125 + 2 = 127$
  - $FP = 20 + 2 = 22$
  - $TN = 90 + 38 = 128$
  - $FN = 5 + 18 = 23$
  - Suma: $127 + 22 + 128 + 23 = 300$.
- **Métricas:** $\text{Acc} = 0.8500, \text{Prec} = 0.8523, \text{Rec} = 0.8467, F1 = 0.8495$.
