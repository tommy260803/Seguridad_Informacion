# DEFINICIONES FORMALES Y MATEMÁTICAS DE RIESGO
**Proyecto:** PhishPe / RAEA-Phish  
**Disciplina:** Aprendizaje Sensible al Coste y Clasificación Selectiva  
**Autor:** Comité de Auditoría y Desarrollo Científico  

---

## 1. INTRODUCCIÓN Y TAXONOMÍA DE PÉRDIDAS

En la literatura de detección de phishing y toma de decisiones secuenciales bajo incertidumbre, el término "riesgo" se utiliza con frecuencia de manera ambigua. Para asegurar la máxima precisión científica, se establecen cuatro definiciones formales y mutuamente diferenciadas:

---

## 2. DEFINICIÓN 1: RIESGO DE CLASIFICACIÓN PURO ($R_{\text{class}}$)

El **Riesgo de Clasificación Puro** evalúa la pérdida esperada originada exclusivamente por los errores de decisión terminal en un escenario de cobertura completa forzada ($\phi = 100\%$), sin considerar costes de adquisición de modalidades ni penalizaciones de abstención:

$$R_{\text{class}} = \frac{1}{N} \sum_{i=1}^N L_{\text{asym}}(y_i, \hat{y}_i)$$

Donde la función de pérdida asimétrica $L_{\text{asym}}$ se define como:
$$L_{\text{asym}}(y, \hat{y}) = \begin{cases}
\gamma \cdot C_{\text{FP}}, & \text{si } y = 1 \text{ y } \hat{y} = 0 \quad (\text{Falso Negativo}) \\
C_{\text{FP}}, & \text{si } y = 0 \text{ y } \hat{y} = 1 \quad (\text{Falso Positivo}) \\
0, & \text{si } y = \hat{y} \quad (\text{Acierto})
\end{cases}$$

Con $C_{\text{FP}} = 1.0$ y $\gamma = 15.0$:
$$R_{\text{class}} = \frac{\gamma \cdot FN + 1.0 \cdot FP}{N} = \frac{15 \cdot FN + FP}{N}$$

---

## 3. DEFINICIÓN 2: RIESGO SELECTIVO CON ABSTENCIÓN PENALIZADA ($R_{\text{selective, penalty}}$)

Cuando el clasificador tiene la facultad de abstenerse frente a muestras de alta incertidumbre, la abstención no se considera un acierto ni un error de clasificación, sino una acción de transferencia o diferimiento con coste acotado $C_{\text{abst}}$ ($C_{\text{abst}} < C_{\text{FP}} \ll C_{\text{FN}}$):

$$R_{\text{selective, penalty}} = \frac{1}{N} \left[ \sum_{i \in \text{Decididos}} L_{\text{asym}}(y_i, \hat{y}_i) + \sum_{j \in \text{Abstenidos}} C_{\text{abst}} \right]$$

$$R_{\text{selective, penalty}} = \frac{(\gamma \cdot FN_{\text{sel}} + C_{\text{FP}} \cdot FP_{\text{sel}}) + N_{\text{abst}} \cdot C_{\text{abst}}}{N}$$

Para la configuración base de RAEA ($\gamma = 15, C_{\text{FP}} = 1.0, C_{\text{abst}} = 0.35$):
$$R_{\text{selective, penalty}} = \frac{(15 \cdot 5 + 1 \cdot 20) + 60 \cdot 0.35}{300} = \frac{95.0 + 21.0}{300} = \frac{116.0}{300} \approx 0.3867$$

---

## 4. DEFINICIÓN 3: RIESGO SELECTIVO CONDICIONAL ($R_{\text{conditional}}$)

El **Riesgo Selectivo Condicional** mide la tasa de pérdida media exclusivamente sobre la subpoblación en la que el clasificador decide emitir un veredicto ($N_{\text{dec}}$):

$$R_{\text{conditional}} = \frac{1}{N_{\text{dec}}} \sum_{i \in \text{Decididos}} L_{\text{asym}}(y_i, \hat{y}_i) = \frac{\gamma \cdot FN_{\text{sel}} + C_{\text{FP}} \cdot FP_{\text{sel}}}{N_{\text{dec}}}$$

Para RAEA con $N_{\text{dec}} = 240$:
$$R_{\text{conditional}} = \frac{15 \cdot 5 + 1 \cdot 20}{240} = \frac{95.0}{240} \approx 0.3958$$

---

## 5. DEFINICIÓN 4: RIESGO OPERACIONAL TOTAL ($R_{\text{operational}}$)

El **Riesgo Operacional Total** representa la función objetivo integral del sistema en producción, combinando el riesgo de clasificación (o abstención) y el coste normalizado de los recursos de cómputo y red invertidos en adquirir las modalidades:

$$R_{\text{operational}} = R_{\text{selective, penalty}} + \lambda \cdot \bar{C}_{\text{acq}}$$

Donde:
- $\bar{C}_{\text{acq}} = \frac{1}{N} \sum_{i=1}^N C(m_i)$ es el coste medio de adquisición consumido por transacción.
- $\lambda$ es el multiplicador de coste computacional ($\lambda = 0.25$ por defecto).

Para RAEA con $\bar{C}_{\text{acq}} \approx 0.4072$:
$$R_{\text{operational}} = 0.3867 + 0.25 \cdot 0.4072 \approx 0.3867 + 0.1018 = 0.4885$$
