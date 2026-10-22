# Resultados Definitivos y Científicamente Verificados
**Proyecto:** PhishPe / PhishGuard Pro  
**Auditoría Científica:** Reconciliación Integral Post-Revisión Independiente  
**Fecha:** Octubre 2026  
**Destino Académico:** *Revista Politécnica* (Escuela Politécnica Nacional, Ecuador)  
**Estado:** Todos los resultados han sido auditados, recalculados y verificados al 100% contra predicciones deterministas y modelos congelados.

---

## 1. Declaración de Veracidad y Ground Truth Experimental

El presente documento establece el conjunto unificado y definitivo de resultados experimentales que deben ser utilizados para la redacción y defensa del artículo científico de PhishPe. Se certifica que:
1. **Cero resultados manuales o sintéticos:** Toda métrica deriva de predicciones individuales registradas en manifiestos CSV y evaluadas con funciones deterministas de `scikit-learn` y `scipy`.
2. **Reconciliación de Erratas Previas:** Se subsana la errata de transcripción que asignaba $FN=19$ a la Política C. La predicción individual pareada sobre los 691 registros establece con exactitud $FN=22$.
3. **Desacoplamiento Estricto de Cohortes Externas:** Se distingue formalmente entre la Cohorte Histórica ($N=1,200$, que incluía 297 binarios de malware de URLhaus) y la Cohorte Auditada Phishing Limpio ($N=1,200$, enfocada en robo de credenciales y anclada con dominios institucionales `.gov` y `.edu`).
4. **Estatus Epistemológico Riguroso:** La prueba de no-inferioridad se declara como **Análisis Exploratorio Post-Hoc** ($\delta = 0.02$) al no contar con pre-registro pre-experimental, y la disponibilidad diferencial de red se caracteriza como **asociación estadística consistente con pérdida no aleatoria / sesgo de supervivencia**, sin pretender una demostración matemática formal de MNAR.

---

## 2. Resumen Canónico de Clasificadores y Políticas (Partición *Host-Unseen* $N=691$)

La partición de prueba independiente *host_unseen* consta de **691 URLs completas** (191 phishing, 500 legítimas) con **0% de solapamiento de nombres de dominio registrados** respecto al conjunto de entrenamiento.

| Modelo / Política | Modalidades Utilizadas | $N$ | TP | TN | FP | FN | Exactitud | Precisión | Recall | $F_1$-Score [95% CI] | FPR | FNR | Ahorro DOM HTML |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **$M_0$ Léxico Puro** | URL Authority (11 feats) | 691 | 158 | 484 | 16 | 33 | 0.9291 | 0.9080 | 0.8272 | **0.8658** [0.8278, 0.9011] | 0.0320 | 0.1728 | 100.0% |
| **$M_1$ Infraestructura** | URL + DNS + SSL (36 feats) | 691 | 167 | 497 | 3 | 24 | 0.9609 | 0.9824 | 0.8743 | **0.9252** [0.8967, 0.9515] | 0.0060 | 0.1257 | 100.0% |
| **$M_2$ Monolítico DOM** | URL + Infra + DOM (62 feats)| 691 | 170 | 496 | 4 | 21 | 0.9638 | 0.9770 | 0.8901 | **0.9315** [0.9036, 0.9565] | 0.0080 | 0.1099 | 0.0% |
| **$M_3$ Visual CDP ($N=83$)**| M2 + Chrome CDP (75 feats) | 83 | 22 | 55 | 0 | 6 | 0.9277 | 1.0000 | 0.7857 | **0.8800** [0.8000, 0.9412] | 0.0000 | 0.2143 | 0.0% |
| **Política B (Cascada Orig.)**| $M_0 \to M_1 \to M_2$ ($H \le 0.15$) | 691 | 166 | 497 | 3 | 25 | 0.9595 | 0.9822 | 0.8691 | **0.9222** [0.8943, 0.9499] | 0.0060 | 0.1309 | **75.83%** |
| **Política C (Asimétrica)\***| $p_0 \le 0.005$ guarda benigna | 691 | **169** | **497** | **3** | **22** | **0.9638** | **0.9826** | **0.8848** | **0.9311** [0.9028, 0.9574] | **0.0060** | **0.1152** | **67.87%** |
| **Política D (Selectiva)\*\***| $M_2$ + Rechazo ($H_2 > 0.50$) | 666 | 159 | 490 | 0 | 17 | 0.9745 | 1.0000 | 0.9034 | **0.9493** [0.9235, 0.9714] | 0.0000 | 0.0966 | 75.83% |

*\*Nota Política C: Rescata exactamente 3 falsos negativos respecto a Política B (TP sube de 166 a 169, FN se reduce de 25 a 22).*  
*\*\*Nota Política D: Evaluada sobre 666 casos decididos (cobertura del 96.38%, 25 muestras derivadas al SOC por incertidumbre).*

---

## 3. Reconciliación de Cohortes Externas de Validación ($N=1,200$)

Se auditaron y separaron explícitamente las dos cohortes externas del proyecto:

### 3.1. Cohorte Histórica ($N=1,200$, Feed-Based Tradicional)
- **Composición:** PhishTank (260), OpenPhish (43), URLhaus malware (297), Tranco (389), Majestic (211).
- **Desempeño Global:** Exactitud = $0.8850$, Precisión = $0.9894$, Recall = $0.7783$, $F_1 = 0.8713$, $\text{FPR} = 0.0083$.
- **Hallazgo Crítico:** Las 297 muestras de URLhaus corresponden a droppers y ejecutables binarios directos (`.exe`, `.apk`), carentes de formularios web de suplantación. Al excluir este feed de malware ($N=903$), la precisión de detección de phishing es de $0.9774$ con $F_1 = 0.8244$.

### 3.2. Cohorte Auditada Phishing Limpio ($N=1,200$, Credencial Puro)
- **Composición:** PhishTank verificado (557), OpenPhish live stream (43), Tranco (195), HIPO Universidades `.edu` (150), CISA `.gov` oficial (150), Majestic (105). Total: 600 phishing verificado / 600 legítimo verificado.
- **Fuga de Información:** **0 dominios solapados** con el corpus de entrenamiento (100% disjunto estricto).
- **Desempeño Global:** Exactitud = $0.8283$, Precisión = $0.9876$, Recall = $0.6650$, $F_1 = 0.7948$, $\text{FPR} = 0.0083$.
- **Desglose por Fuente:**
  - *PhishTank ($N=557$):* $\text{Recall} = 0.6445$, $F_1 = 0.7838$.
  - *OpenPhish ($N=43$):* $\text{Recall} = 0.9302$, $F_1 = 0.9639$.
  - *CISA `.gov` ($N=150$):* $\text{FPR} = 0.0000$ (0 falsas alarmas).
  - *HIPO Universidades `.edu` ($N=150$):* $\text{FPR} = 0.0267$ (4 falsas alarmas por estructuras complejas).
  - *Tranco Top 1M ($N=195$):* $\text{FPR} = 0.0051$ (1 falsa alarma).
  - *Majestic ($N=105$):* $\text{FPR} = 0.0000$ (0 falsas alarmas).

### 3.3. Manifiestos de Predicciones Individuales Fila por Fila
Ambas cohortes cuentan con archivos de predicciones individuales completamente auditables en `data_manifests/`:
- `cohort_historical_n1200_individual_predictions.csv` (3,600 filas: 1,200 URLs $\times$ $M_0$ Original, $M_0$ Normalizado y HybridM0 Config C).
- `cohort_clean_phishing_n1200_individual_predictions.csv` (2,400 filas: 1,200 URLs $\times$ $M_0$ Original y $M_0$ Normalizado).
- Esquema unificado: `id, canonical_url, source, verified_label, model_version, phishing_probability, final_prediction, partition, original_experiment_ref`.
- Se declara que las predicciones individuales a nivel de registro para HybridM0 sobre la cohorte limpia constituyen *evidencia solo documentada*, al depender de heurísticas dinámicas de red en vivo ejecutadas en el sondeo original sin haberse exportado el vector de probabilidades crudo.

---

## 4. Inferencia Estadística y Análisis Exploratorio de No-Inferioridad

1. **Aporte de la Infraestructura de Red ($M_0 \to M_1$):**  
   $$\Delta F_1 = +0.0594 \quad [\text{IC}_{95\%}: +0.0348, +0.0877], \quad \chi^2 = 16.96, \quad p = 1.0 \times 10^{-5}$$  
   *Superioridad confirmada* (rechaza $H_0$ con $\alpha = 0.05$ tras ajuste Benjamini-Hochberg FDR).
2. **Aporte Marginal del Contenido HTML DOM ($M_1 \to M_2$):**  
   $$\Delta F_1 = +0.0063 \quad [\text{IC}_{95\%}: -0.0137, +0.0270], \quad \chi^2 = 0.071, \quad p = 0.7905$$  
   *No significativo* (el contenido HTML no aporta una ganancia estadísticamente detectable sobre la infraestructura).
3. **Análisis Exploratorio de No-Inferioridad (Política C vs Monolítico $M_2$):**  
   $$\Delta F_1 = -0.0004 \quad [\text{IC}_{97.5\% \text{ unilateral}} = -0.0085 > -0.0200, \quad p < 0.001]$$  
   *No-inferioridad respaldada de forma exploratoria* bajo margen post-hoc $\delta = 0.02$, evitando el $67.87\%$ de las descargas HTML.

---

## 5. Disponibilidad Multimodal en Vivo y Robustez ante Sitios Caídos ($N=600$)

- **Asociación Empírica:** En sondeo en vivo ($N=600$: 300 phishing, 300 benigno), solo 40 sitios de phishing tenían HTML descargable (13.3%), frente a 207 sitios legítimos (69.0%). La prueba exacta de Fisher arroja $p = 4.28 \times 10^{-46}$ y $\text{Odds Ratio} = 14.47$.
- **Patrón Consistente con MNAR:** La falta de modalidades no ocurre al azar, sino que está correlacionada fuertemente con la naturaleza efímera del ataque (takedowns y suspensiones de DNS).
- **Estrategia C (Fallback Jerárquico a $M_0$):** Resuelve el 100% de la población ($N=600$) alcanzando **Precisión = $93.64\%$**, **$\text{FPR} = 5.00\%$** y **$F_1 = 0.8246$**.
- **Inviabilidad de Imputación con Ceros (Estrategia F):** Dispara el FPR al **$18.67\%$** (56 sitios benignos bloqueados) y queda formalmente descartada para producción.

---

## 6. Rendimiento y Usabilidad de Sistemas

- **Nivel A (Algorítmico CPU):** Inferencia léxica $M_0$ en **$0.18 \text{ ms}$**; extracción y predicción total en **$14.74 \text{ ms}$**.
- **Nivel B (Red e I/O Externa):** Consultas DNS medianas de **$213.6 \text{ ms}$**; negociación TLS en **$981.7 \text{ ms}$**; telemetría de red total en **$1,272.7 \text{ ms}$**; captura visual Chrome CDP en **$2,166.4 \text{ ms}$** (inviable síncronamente).
- **Nivel C (API y Extensión):** FastAPI `/check` responde en **$19.75 \text{ ms}$** de mediana ($P_{90} = 26.46 \text{ ms}$), satisfaciendo el umbral de usabilidad de Nielsen (< 100 ms).
