# RECONCILIACIÓN Y CORRECCIONES DE RIESGO PONDERADO
**Proyecto:** PhishPe / RAEA-Phish  
**Fecha:** 22 de Octubre de 2026  
**Fase:** 3 (Auditoría y Corrección del Riesgo Ponderado)  

---

## 1. RECONCILIACIÓN MATEMÁTICA DEL VALOR 0.3867

La auditoría forense ha comprobado que el valor $0.386667$ reportado para RAEA-Phish proviene de la formulación exacta de **Riesgo Selectivo con Abstención Penalizada**:

$$R_{\text{selective, penalty}} = \frac{\gamma \cdot FN_{\text{sel}} + C_{\text{FP}} \cdot FP_{\text{sel}} + N_{\text{abst}} \cdot C_{\text{abst}}}{N}$$

Con los valores confirmados experimentalmente:
- $FN_{\text{sel}} = 5$
- $FP_{\text{sel}} = 20$
- $N_{\text{abst}} = 60$
- $\gamma = 15.0$
- $C_{\text{FP}} = 1.0$
- $C_{\text{abst}} = 0.35$
- $N = 300$

$$\text{Pérdida sobre decididos} = (5 \cdot 15.0) + (20 \cdot 1.0) = 75.0 + 20.0 = 95.0$$
$$\text{Coste de abstención} = 60 \cdot 0.35 = 21.0$$
$$\text{Pérdida Total} = 95.0 + 21.0 = 116.0$$
$$R = \frac{116.0}{300} = 0.3866667 \approx 0.3867$$

---

## 2. RECONCILIACIÓN FRENTE A M1 FIJO ($1.3167$)

El modelo M1 Fijo clasifica obligatoriamente el 100% de las 300 instancias ($\phi = 1.0$, $N_{\text{abst}} = 0$):
- $FN = 25$
- $FP = 20$
- $\text{Pérdida Total} = (25 \cdot 15.0) + (20 \cdot 1.0) = 375.0 + 20.0 = 395.0$
$$R_{\text{M1}} = \frac{395.0}{300} = 1.3166667 \approx 1.3167$$

### Comparación Crítica
1. **En Régimen Selectivo:** RAEA transfiere 20 sitios de phishing ambiguos y 40 sitios legítimos ambiguos a la cola de abstención. Esto reduce los falsos negativos terminales de 25 a únicamente 5, logrando una reducción del riesgo ponderado del **$70.63\%$** ($0.3867$ frente a $1.3167$).
2. **Bajo Despliegue Forzado Fail-Open:** Si se asume que las abstenciones se marcan forzadamente como legítimas, RAEA absorbe los 20 falsos negativos y 40 verdaderos negativos adicionales, resultando en exactamente el mismo riesgo que M1 ($1.3167$).
3. **Bajo Despliegue Forzado Fail-Closed:** Si se asume que las abstenciones se bloquean preventivamente (clasificadas como phishing), RAEA incurre en solo 5 falsos negativos y 60 falsos positivos, alcanzando un riesgo total de **$0.4500$** a cobertura del 100%, superando ampliamente a M1 ($1.3167$).

---

## 3. SENSIBILIDAD AL RATIO DE COSTE $\gamma$ Y A $C_{\text{abst}}$

El análisis de sensibilidad (`cost_sensitivity.csv`) demuestra que la ventaja de RAEA sobre M1 se amplifica conforme el coste del falso negativo ($\gamma$) aumenta:

| $\gamma$ ($C_{\text{FN}}/C_{\text{FP}}$) | $C_{\text{abst}}$ | Riesgo M1 Fijo | Riesgo RAEA Selectivo | Riesgo RAEA Fail-Closed | Ventaja RAEA Selectivo (%) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 1.0 (Simétrico) | 0.35 | 0.1500 | 0.1533 | 0.2167 | -2.2% |
| 5.0 | 0.35 | 0.4833 | 0.2200 | 0.2833 | **+54.5%** |
| 10.0 | 0.35 | 0.9000 | 0.3033 | 0.3667 | **+66.3%** |
| 15.0 (Base) | 0.35 | 1.3167 | 0.3867 | 0.4500 | **+70.6%** |
| 20.0 | 0.35 | 1.7333 | 0.4700 | 0.5333 | **+72.9%** |
| 50.0 | 0.35 | 4.2333 | 0.9700 | 1.0333 | **+77.1%** |

> [!NOTE]
> En costes estrictamente simétricos ($\gamma=1.0$), M1 y RAEA son prácticamente idénticos en riesgo (0.1500 vs 0.1533). La contribución científica y práctica de RAEA se materializa en dominios de seguridad real donde $\gamma \ge 5.0$, protegiendo contra incidentes severos de phishing.
