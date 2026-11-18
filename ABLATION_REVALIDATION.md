# REVALIDACIÓN DEL ESTUDIO DE ABLACIÓN Y ANÁLISIS DE GUARDAS
**Proyecto:** PhishPe / RAEA-Phish  
**Fecha:** 22 de Octubre de 2026  
**Fase:** 6 (Revalidación del Estudio de Ablación)  

---

## 1. EXPLICACIÓN DE LA IDENTIDAD AGREGADA ENTRE A5 Y A6

Uno de los puntos centrales de la auditoría fue determinar por qué la variante A5 (*RAEA sin guarda contra salida benigna prematura*) arrojó métricas agregadas idénticas a A6 (*RAEA completo*).

### 1.1. Causa Raíz Matemática
La función de decisión de RAEA evalúa en la etapa $t=0$ (modelo léxico $M_0$) cuatro valores $Q$:
1. $Q(\text{phishing}) = C_{\text{FP}} \cdot (1 - p_0) = 1.0 \cdot (1 - p_0)$
2. $Q(\text{benign}) = \gamma \cdot C_{\text{FP}} \cdot p_0 = 15.0 \cdot p_0$ (si no hay guarda)
3. $Q(\text{abstain}) = C_{\text{abst}} = 0.35$
4. $Q(\text{acquire network}) = \mathbb{E}[R_{\text{post}}] + \lambda \cdot \hat{C}_{\text{network}}$

Para que la política elija la salida benigna prematura en $M_0$ sin guarda (A5), se debe cumplir necesariamente que:
$$Q(\text{benign}) \le Q(\text{abstain}) \implies 15.0 \cdot p_0 \le 0.35 \implies p_0 \le \frac{0.35}{15.0} \approx 0.02333$$

Por otra parte, la guarda benigna explícita de A6 fija el umbral de seguridad en:
$$p_{\text{safe}} = 0.02000$$

### 1.2. Hallazgo Forense sobre los Datos (`guard_activation_log.csv`)
En la partición de prueba confirmatoria ($N=300$):
- **75 muestras** tuvieron $p_0 \le 0.0200$. Para todas ellas, ninguna presentó banderas de riesgo léxico (`has_lexical_risk = False`), por lo que tanto A5 como A6 autorizaron la salida benigna temprana.
- **4 muestras** cayeron en la ventana residual $0.0200 < p_0 \le 0.02333$. Sin embargo, para estas 4 muestras, el valor esperado de adquirir información de red $Q(\text{acquire network})$ fue inferior al riesgo terminal ($Q_{\text{acq}} < 15.0 \cdot p_0$), provocando que ambas políticas decidieran adquirir la modalidad de red.
- **221 muestras** tuvieron $p_0 > 0.02333$. Para todas ellas, el riesgo asimétrico de falso negativo ($15.0 \cdot p_0 > 0.35$) superó el coste de abstención y de adquisición, impidiendo la salida benigna de manera natural.

### Conclusión Teórica y Práctica
La guarda contra salida benigna prematura no es inútil: **es un mecanismo formal de defensa en profundidad**. En condiciones calibradas con $\gamma=15$ y $C_{\text{abst}}=0.35$, la política Bayes-óptima converge de forma endógena a la misma frontera de decisión que la guarda heurística.

---

## 2. PREVENCIÓN DE FALSOS NEGATIVOS PREMATUROS EN ETAPA 0

El estudio revalidado confirma una de las mayores fortalezas metodológicas de RAEA frente a las cascadas basadas en entropía:

| Política / Variante | Falsos Negativos en Etapa 0 ($M_0$) | FN Totales | Recall | F1 Selectivo |
|---|:---:|:---:|:---:|:---:|
| **A0: Cascada de Entropía (B3)** | **12** | 29 | 0.8067 | 0.8831 |
| **A5: RAEA sin guarda explícita** | **3** | 25 | 0.8333 | **0.9091** |
| **A6: RAEA Completo** | **3** | 25 | 0.8333 | **0.9091** |
| **A7: M2 Forzado Completo** | 0 | 23 | 0.8467 | 0.8439 |

> [!IMPORTANT]
> RAEA reduce los falsos negativos tempranos en la etapa puramente léxica de **12 a 3** (reducción del $75\%$), evitando que sitios de phishing con URLs sintácticamente engañosas sean catalogados prematuramente como benignos sin consultar la infraestructura de red.
