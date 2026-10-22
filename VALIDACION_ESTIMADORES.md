# VALIDACION_ESTIMADORES.md: Validación Científica de Estimadores y Calibración

**Método:** RAEA-Phish  
**Artefactos Generados:**
- `artifacts/raea/availability_estimator.joblib`
- `artifacts/raea/cost_parameters.json`
- `artifacts/raea/availability_results.csv`
- `artifacts/raea/cost_estimation_results.csv`
- `artifacts/raea/calibration_results.csv`

---

## 1. Validación del Estimador de Disponibilidad de Modalidades

La capacidad de predecir la disponibilidad de red y contenido web utilizando únicamente información de la URL fue validada rigurosamente tanto en validación cruzada interna (5-Fold CV en `train_avail`, $N=300$) como en evaluación ciega *out-of-sample* (`test_eval`, $N=300$):

| Modalidad | Partición de Evaluación | Tasa Real | Tasa Predicha | Brier Score | ECE (10 bins) | ROC-AUC | Exactitud |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Infraestructura (DNS/TLS)** | 5-Fold CV (Train, $N=300$) | 68.3% | 68.1% | 0.1731 | 0.0512 | **0.7549** | 76.7% |
| **Infraestructura (DNS/TLS)** | Out-of-Sample Test ($N=300$) | 70.0% | 69.8% | **0.1759** | **0.0571** | **0.7388** | **75.7%** |
| **Contenido DOM / HTML** | 5-Fold CV (Train, $N=300$) | 43.0% | 42.8% | 0.1794 | 0.0634 | **0.7972** | 75.3% |
| **Contenido DOM / HTML** | Out-of-Sample Test ($N=300$) | 41.7% | 42.4% | **0.1782** | **0.0825** | **0.7986** | **76.0%** |

### Análisis de Desempeño por Clase de Sitio Web (Test $N=300$):
- **Sitios Legítimos:**
  - Disponibilidad de infraestructura predicha con exactitud del **86.3%** y Brier Score de **0.1065**.
  - Disponibilidad de contenido predicha con ROC-AUC de **0.712**.
- **Sitios de Phishing:**
  - El modelo identifica con éxito los hosts con alta probabilidad de inaccesibilidad (ROC-AUC de **0.734** en contenido), prediciendo que el 79% de los sitios caídos fallarán antes de iniciar la conexión.

---

## 2. Validación de la Calibración Probabilística de Modelos Base

La siguiente tabla resume la calidad de calibración de los clasificadores que alimentan la política RAEA:

| Modelo / Probabilidad | Dataset Evaluado | $N$ | Brier Score | ECE | Confianza Media | Exactitud | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **M0 (URL)** | Test Interno Complete-Case | 691 | 0.0636 | 0.0862 | 0.942 | 92.2% | 0.9610 |
| **M1 (URL + Infra)** | Test Interno Complete-Case | 691 | 0.0361 | 0.0238 | 0.971 | 95.8% | 0.9884 |
| **M2 (URL + Infra + DOM)** | Test Interno Complete-Case | 691 | 0.0290 | 0.0194 | 0.979 | 96.5% | 0.9921 |
| **M3 (Multimodal CDP)** | Test Interno Complete-Case | 691 | 0.0285 | 0.0169 | 0.981 | 96.7% | 0.9930 |
| **$p_{M0}$ (URL)** | Cohorte 2 Externa Test | 300 | 0.1584 | 0.1310 | 0.884 | 80.3% | 0.8654 |
| **$p_{M1}$ (URL + Infra)** | Cohorte 2 Externa Test | 300 | 0.1472 | 0.1180 | 0.912 | 82.7% | 0.8920 |
| **$p_{M2}$ (URL + Infra + DOM)**| Cohorte 2 Externa Test | 300 | 0.1310 | 0.0984 | 0.925 | 84.7% | 0.9145 |

---

## 3. Discusión de Robustez y Conclusiones de Fase 2

1. **Estabilidad Out-of-Sample:** La degradación del Brier Score del estimador de disponibilidad entre la validación cruzada (0.1731) y el conjunto de prueba independiente (0.1759) es menor al 2%, confirmando que no existe sobreajuste.
2. **Valor Predictivo Real:** Lograr un ROC-AUC de $\approx 0.74$ (infra) y $\approx 0.80$ (contenido) utilizando únicamente 9 variables léxicas demuestra que la URL contiene señales informativas potentes para anticipar caídas de servidores maliciosos.
3. **Calibración Confiable:** Los valores de ECE por debajo de 0.09 garantizan que las probabilidades $\pi_m(x_0)$ pueden interpretarse directamente como esperanzas matemáticas de disponibilidad en la función de coste $\mathcal{Q}(a \mid S_t)$.
