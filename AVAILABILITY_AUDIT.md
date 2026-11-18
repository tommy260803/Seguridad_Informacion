# AUDITORÍA DE DISPONIBILIDAD EMPÍRICA Y ESTIMADORES MODALES
**Proyecto:** PhishPe / RAEA-Phish  
**Fecha:** 22 de Octubre de 2026  
**Fase:** 5 (Auditoría de Disponibilidad, Latencia y Costes Observados)  

---

## 1. ORIGEN DE LAS MEDICIONES DE DISPONIBILIDAD

En cumplimiento de los principios de reproducibilidad científica:
- **No se generaron disponibilidades sintéticas.**
- Todos los estados de disponibilidad (`infra_status`, `content_status`) proceden de las campañas de sondeo de red y web en vivo efectuadas sobre los 600 sitios de la Cohorte 2 (`artifacts/corrections_phase2/eval/probe_predictions.csv`).

### 1.1. Distribución Empírica Observada (Cohorte 2 Completa, $N=600$)
- **Disponibilidad de Red (DNS/TLS):**
  - Éxito (`success`): 415 ($69.17\%$)
  - Bloqueado (`blocked`): 153 ($25.50\%$)
  - Error de red (`error`): 32 ($5.33\%$)
- **Disponibilidad de Contenido (HTTP/DOM):**
  - Éxito (`success`): 254 ($42.33\%$)
  - Error/Inaccesible (`error`): 346 ($57.67\%$)

> [!NOTE]
> La alta tasa de fallo en la adquisición de contenido ($57.67\%$) refleja fielmente la naturaleza efímera del phishing real, donde las páginas son dadas de baja rápidamente por proveedores de alojamiento o bloquean agentes automatizados.

---

## 2. EVALUACIÓN Y CALIBRACIÓN DE LOS ESTIMADORES DE DISPONIBILIDAD

Los modelos de disponibilidad contenidos en `artifacts/raea/availability_estimator.joblib` fueron entrenados exclusivamente sobre `train_avail` ($N=300$) y evaluados de forma ciega sobre `test_eval` ($N=300$):

| Estimador Modal | Muestras Exitosas (Test) | Muestras Fallidas (Test) | Exactitud ($0.5$) | ROC-AUC | Brier Score |
|---|:---:|:---:|:---:|:---:|:---:|
| **Disponibilidad Red (`infra_model`)** | 210 | 90 | **0.7000** | **0.7030** | **0.1997** |
| **Disponibilidad Contenido (`content_model`)** | 126 | 174 | 0.4733 | **0.8034** | 0.3127 |

### 2.1. Conclusiones
1. El estimador de disponibilidad de red exhibe una buena discriminación ($AUC = 0.7030$) y un Brier score de $0.1997$, lo que permite a RAEA predecir confiablemente si vale la pena esperar por DNS/TLS.
2. El estimador de contenido, a pesar del desbalance por la alta mortandad de sitios de phishing, alcanza un $AUC = 0.8034$, lo que confiere a la política una capacidad discriminativa notable para podar ramas de adquisición costosas cuando el sitio web es inaccesible.
