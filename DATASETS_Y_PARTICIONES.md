# DATASETS_Y_PARTICIONES.md: Manifiesto de Datos y Particionamiento Experimental

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Directriz Ética y Científica:** Cero fuga de información (*zero data leakage*), particiones congeladas y separación estricta entre entrenamiento de estimadores y conjuntos de evaluación confirmatoria.

---

## 1. Inventario de Conjuntos de Datos

| Dataset | Código | Tamaño Total ($N$) | Etiquetas | Propósito en el Estudio | Estado / Ruta |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Corpus Base 0.1.0** | `D0` | 176,201 | 88,100 Legítimas, 88,101 Phishing | Entrenamiento histórico de modelos base $M0$ a $M3$ | Congelado (`data/processed/0.1.0/`) |
| **Complete-Case Multimodal** | `D_CC` | 1,393 | 702 Validación, 691 Test | Evaluación histórica y calibración base multimodal | Congelado (`artifacts/m0-real/` a `m3-real/`) |
| **Intention-to-Evaluate (ITE)** | `D_ITE` | 1,500 | 750 Legítimas, 750 Phishing | Evaluación de robustez ante fallos multimodales | Congelado (`artifacts/m4-real/`, `m5-real/`) |
| **Cohorte Externa 1 (Sondeo)** | `D_C1` | 240 | 120 Legítimas, 120 Phishing | Prueba de transferencia externa de disponibilidad | Congelado (`external_multimodal_probe_n240.jsonl`) |
| **Cohorte Externa 2 (Sondeo)** | `D_C2` | 600 | 300 Legítimas, 300 Phishing | Entrenamiento de estimadores y test comparativo de políticas | Congelado (`artifacts/corrections_phase2/eval/`) |

---

## 2. Particionamiento Disjunto de la Cohorte 2 para RAEA-Phish

Para garantizar que los estimadores de disponibilidad y coste no se evalúen sobre los mismos datos utilizados para su ajuste, se aplicó una partición estratificada 50/50 sobre las 600 URLs de la Cohorte 2 (semilla fijada `seed=42`, estratificada por clase `label`):

1. **Partición `train_avail` ($N=300$):**
   - 150 URLs Legítimas (fuentes: Majestic Million, CISA .gov, World Universities .edu).
   - 150 URLs de Phishing (fuentes: OpenPhish, PhishTank, URLhaus, CERT Polska).
   - **Uso exclusivo:** Entrenamiento y calibración de los estimadores de disponibilidad $\pi_{\text{infra}}(x_0)$ y $\pi_{\text{content}}(x_0)$, y ajuste de hiperparámetros $(\lambda, \gamma, p_{\text{safe}})$ mediante validación cruzada interna (5-Fold CV).

2. **Partición `test_eval` ($N=300$):**
   - 150 URLs Legítimas.
   - 150 URLs de Phishing.
   - **Uso exclusivo:** Evaluación confirmatoria *out-of-sample* de RAEA-Phish contra los baselines (B0–B5), estudios de ablación (A0–A7), análisis estadístico pareado y matrices de confusión definitivas.

El mapeo individual de cada URL a su partición se encuentra auditado en `artifacts/raea/raea_partitions.csv`.

---

## 3. Garantías de Integridad y No-Fuga (*Leakage Prevention*)

- **Sin Características Futuras:** Los estimadores de disponibilidad solo reciben el vector $x_0 \in \mathbb{R}^9$ observable en la URL (`host_length`, `url_length`, `host_entropy`, `has_ip_host`, `uses_https`, `p_m0`, `dot_count`, `host_label_count`, `subdomain_count`).
- **Inmutabilidad de Modelos Base:** Los pesos y binarios de $M0$, $M1$, $M2$ y $M3$ permanecen idénticos a los del commit congelado `058169a99786a42203d7db27d5da994b6ceb61c9`.
- **Independencia de Test:** Ningún hiperparámetro de RAEA-Phish fue seleccionado examinando el conjunto `test_eval`.
