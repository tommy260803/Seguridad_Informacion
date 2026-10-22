# ABLATION_PROTOCOL.md: Protocolo Científico del Estudio de Ablaciones

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Fase:** Fase 5 - Descomposición y Contribución de Componentes  
**Objetivo:** Aislar el impacto individual de cada premisa matemática y mecanismo algorítmico del método propuesto frente a la cascada original y el clasificador monolítico.

---

## 1. Variantes de Ablación Evaluadas

Todas las variantes fueron evaluadas de manera idéntica y simultánea sobre la partición confirmatoria congelada `test_eval` ($N=300$ muestras disjuntas de la Cohorte 2 externa, 150 phishing y 150 legítimas), utilizando los mismos clasificadores base preentrenados ($M0$, $M1$, $M2$):

| Variante | Identificador | Modificación de Hipótesis / Configuración |
| :--- | :--- | :--- |
| **A0** | Cascada Original | Cascada estándar PhishPe basada exclusivamente en Entropía de Shannon ($H \le 0.15$). |
| **A1** | RAEA sin Disponibilidad | Se fija $\pi_m(x_0) = 1.0$, asumiendo disponibilidad perfecta como en la literatura clásica. |
| **A2** | RAEA sin Costes Asimétricos | Se fija $\gamma = 1.0$ ($C_{FN} = C_{FP} = 1.0$), imponiendo una función de pérdida simétrica. |
| **A3** | RAEA sin Abstención | Se elimina la opción $\hat{y} = \bot$, forzando una decisión binaria bajo cualquier nivel de incertidumbre. |
| **A4** | RAEA sin Beneficio Informativo | Se omite el cálculo del riesgo posterior esperado, decidiendo únicamente con el riesgo estático local. |
| **A5** | RAEA sin Guarda Benigna | Se desactiva la condición de guarda en $M0$, permitiendo salidas legítimas inmediatas con $p_0 \le 0.5$. |
| **A6** | RAEA Completo | **Método propuesto integrado** ($\gamma=15, \lambda=0.25, p_{\text{safe}}=0.02, C_{\text{abst}}=0.35, \pi_m$). |
| **A7** | M2 Forzado Monolítico | Se adquieren siempre todas las modalidades ($M0 \to M1 \to M2$) sin detención temprana ni abstención. |

---

## 2. Métricas de Impacto por Componente

Para cada componente aislado se miden:
1. Variación en F1-Score: $\Delta F1 = F1(A6) - F1(A_k)$.
2. Reducción de Pérdida Ponderada: $\Delta \mathcal{R}_{\text{w}} = \mathcal{R}_{\text{w}}(A_k) - \mathcal{R}_{\text{w}}(A6)$.
3. Falsos Negativos Prevenidos: $\Delta FN = FN(A_k) - FN(A6)$.
4. Falsos Negativos Prematuros en $M0$ Prevenidos: $\Delta FN_0 = FN_0(A_k) - FN_0(A6)$.
5. Sobrecarga o Ahorro Computacional: $\Delta \mathcal{C} = \mathcal{C}(A_k) - \mathcal{C}(A6)$ y modalidades promedio.
