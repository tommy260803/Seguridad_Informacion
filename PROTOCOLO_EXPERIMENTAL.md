# PROTOCOLO_EXPERIMENTAL.md: Protocolo de Evaluación Experimental Comparativa

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Fase:** Fase 4 - Evaluación Comparativa contra Baselines  
**Conjunto de Prueba Primario:** `test_eval` Cohorte 2 ($N=300$, estratificado 50% phishing / 50% legítimo, 0% solapamiento con train de estimadores ni con corpus base 0.1.0).

---

## 1. Definición Formal de Baselines Comparados

| Código | Identificador | Descripción Operativa | Modalidades Forzadas | Criterio de Decisión / Parada |
| :--- | :--- | :--- | :--- | :--- |
| **B0** | `M0_Fixed` | Clasificador de autoridad URL puro | Exclusivamente URL ($m_0$) | Umbral de Bayes $p \ge 0.5$ |
| **B1** | `M1_Fixed` | Clasificador URL + Red estático | Siempre URL + Red ($m_0, m_1$) | Umbral $p \ge 0.5$ (fallback a $M0$ si la red falla) |
| **B2** | `M2_Fixed` | Clasificador exhaustivo multietapa | Siempre URL + Red + DOM ($m_0, m_1, m_2$) | Pipeline monolítico forzado hasta $M2$ |
| **B3** | `Entropy_Cascade` | Cascada Adaptativa estándar de PhishPe | Dinámica ($m_0 \to m_1 \to m_2$) | Entropía de Shannon simétrica: detención si $H(p_t) \le 0.15$; abstención si $H(p_2) > 0.20$ |
| **B4** | `Conservative` | Cascada con restricción benigna simple | Dinámica ($m_0 \to m_1 \to m_2$) | Detención en $M0$ si $H \le 0.15$ para phishing, pero prohíbe salida benigna salvo $p_0 \le 0.02$ |
| **B5** | `Simple_Cost` | Heurística lineal confianza-coste | Dinámica ($m_0 \to m_1 \to m_2$) | Detención si margen de confianza $|p - 0.5| > \tau - c_m$; sin modelo de disponibilidad |
| **B6** | `RAEA_Phish` | **Método propuesto en este estudio** | Dinámica adaptativa | Minimización de $\mathcal{Q}(a \mid S_t)$ con disponibilidad calibrada $\pi_m$, costes asimétricos $\gamma=15$ y Guarda Benigna en $M0$ |

---

## 2. Experimentos Evaluados

- **EXP-01: Rendimiento Predictivo:** Accuracy, Precision, Recall, F1, FPR, FNR, Brier Score, ECE, y Pérdida Ponderada de Riesgo ($\mathcal{R}_{\text{w}}$ con $\gamma = 15.0, C_{\text{abst}} = 0.35$).
- **EXP-02: Falsos Negativos y Salidas Tempranas:** Cuantificación forense del número de sitios de phishing que se escapan silenciosamente en la Etapa 0 ($M0$), Etapa 1 ($M1$) y Etapa 2 ($M2$).
- **EXP-03: Coste Computacional y Latencia:** Medición de latencia P50, P75, P95, P99 y número promedio de modalidades consultadas.
- **EXP-04: Robustez ante Fallos de Disponibilidad:** Análisis de comportamiento ante eventos de fallo de DNS/TLS (`blocked`, `error`) y de descarga HTTP.
- **EXP-05: Generalización Externa:** Desglose del rendimiento predictivo en 6 fuentes disjuntas de la web real (OpenPhish, PhishTank, URLhaus, CERT.pl, Majestic Million, Portales Gubernamentales/Universitarios).
- **EXP-06: Clasificación Selectiva y Riesgo-Cobertura:** Evaluación de curvas de error residual en función de la cobertura (AURC).
- **EXP-07: Sensibilidad a Parámetros:** Respuesta del sistema ante variaciones en la razón de asimetría $\gamma \in [5, 30]$ y el factor de coste $\lambda \in [0.1, 1.0]$.
