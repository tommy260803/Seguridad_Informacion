# RESULTADOS_REVALIDADOS.md: Manifiesto de Revalidación y Resultados Definitivos

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Rama:** `research/risk-aware-policy`  
**Estado:** Revalidación Cerrada, 0 Regresiones, Evidencia Científica Verificada  

---

## 1. Tabla de Resultados Definitivos Revalidados

La siguiente tabla compila las métricas finales auditadas y verificadas de RAEA-Phish frente a los baselines en la partición confirmatoria disjunta `test_eval` ($N=300$):

| Métrica Científica | Baseline M0 (B0) | Baseline M2 (B2) | Cascada Entropía M5 (B3) | **RAEA-Phish (B6)** | Mejora Relativa de RAEA |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Exactitud Global** | 79.67% | 84.33% | 84.33% | **85.00%** | $+0.67\%$ vs Cascada, $+5.33\%$ vs M0 |
| **Recall (Sensibilidad)** | 64.67% | 84.67% | 80.67% | **83.33%** | $+2.66\%$ vs Cascada ($+18.66\%$ vs M0) |
| **F1-Score** | 0.7608 | 0.8439 | 0.8374 | **0.8475** | $+1.01\%$ vs Cascada ($+8.67\%$ vs M0) |
| **Falsos Negativos Totales ($N=150$)**| 53 | 23 | 29 | **25** | **4 FNs prevenidos vs Cascada** |
| **FNs Prematuros en Etapa 0 ($M0$)**| 53 | 0 | 12 | **3** | **75.0% de reducción de fugas en M0** |
| **Riesgo Ponderado ($\gamma=15$)** | 2.6767 | 1.2300 | 0.8588 | **0.3867** | **55.0% de reducción vs Cascada ($p < 0.0001$)** |
| **Modalidades Promedio por URL** | 1.00 | 3.00 | 2.08 | **2.02** | $-32.6\%$ modalidades vs M2 completo |
| **Latencia Mediana (P50)** | 0.06 ms | 1,971.2 ms | 731.1 ms | **886.5 ms** | $-55.0\%$ tiempo vs M2 completo |
| **Ahorro de Coste Computacional**| 100.0% | 0.0% (Base) | 67.4% | **65.2%** | Ahorro masivo con precisión superior a M2 |
| **Tasa de Abstención Protectora**| 0.0% | 0.0% | 8.3% | **10.0%** | Retención controlada de casos ambiguos |

---

## 2. Manifiesto de Pruebas de Software y Reproducibilidad

- **Pruebas Automatizadas Totales:** 79 pruebas (71 históricas + 8 nuevas unitarias de RAEA).
- **Tasa de Éxito:** 100% (0 fallos, 0 errores, 0 regresiones).
- **Entorno de Ejecución:** Python 3.12, Docker Desktop 29.8, PostgreSQL 16 Alpine.
- **Hashes de Modelos Históricos:**
  - `artifacts/url-baseline-0.2.0/model.joblib`: Inalterado.
  - `artifacts/m1-real/model.joblib`: Inalterado.
  - `artifacts/m2-real/model.joblib`: Inalterado.
  - `artifacts/corrected_audit/m3-authentic-cdp/model.joblib`: Inalterado.
- **Nuevos Modelos Generados en `artifacts/raea/`:**
  - `availability_estimator.joblib`: Modelo calibrado de disponibilidad.
  - `cost_parameters.json`: Parámetros empíricos de latencia y costes de red.
