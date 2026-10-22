# Metodología Experimental de Validación Externa Especializada
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Protocolo Científico — Fase 1: Validación Externa*

---

## 1. Objetivos e Hipótesis Científicas

### 1.1. Objetivo General
Evaluar la capacidad de generalización, la fidelidad de detección y la resiliencia ante atajos estructurales de los modelos congelados de PhishPe ($M_0$ léxico original, $M_0$ normalizado y el modelo híbrido $M_0+\text{Brand}+\text{Rules}$ en Configuración C) sobre una cohorte externa rigurosamente curada y libre de solapamientos con el corpus de entrenamiento.

### 1.2. Hipótesis Experimentales
1. **$H_1$ (Efecto del atajo de malware en la cohorte histórica):**  
   La métrica de recall en la cohorte histórica ($N=1,200$) se encuentra sobreestimada debido a la presencia de muestras de URLhaus (ejecutables de botnets alojados en IPs crudas). Al evaluar exclusivamente phishing genuino de credenciales (PhishTank y OpenPhish), el recall léxico disminuirá, revelando la verdadera dificultad del problema sin atajos sintácticos.
2. **$H_2$ (Impacto de la profundidad estructural benigna en la tasa de falsos positivos):**  
   Al introducir sitios web legítimos realistas que contienen rutas profundas y parámetros funcionales (CISA y HIPO), los clasificadores basados puramente en características léxicas ($M_0$) experimentarán un incremento en su tasa de falsos positivos ($\text{FPR}$).
3. **$H_3$ (Eficacia del filtrado híbrido y reputación):**  
   La integración del motor de reputación global (Tranco Top 1M) y las reglas semánticas en `HybridM0Model` amortiguará el impacto de las rutas benignas, manteniendo la tasa de falsos positivos por debajo del umbral operacional crítico del 1% ($\text{FPR} < 0.0100$) y una precisión superior al 97%.

---

## 2. Definición y Partición de Cohortes Experimentales

Para aislar sistemáticamente cada factor de confusión, se diseñaron cuatro esquemas de evaluación comparativa:

```mermaid
graph TD
    subgraph Conjuntos_Evaluacion [Diseño Experimental de Cohortes]
        A[Cohorte A: Histórica Completa<br>N=1200 | Prevalencia=50.0%<br>600 Maliciosas incl. URLhaus vs 600 Bare Legit]
        B[Cohorte B: Histórica sin URLhaus<br>N=903 | Prevalencia=33.55%<br>303 Phishing estricto vs 600 Bare Legit]
        C[Cohorte C: Especializada Phishing<br>N=1200 | Prevalencia=50.0%<br>600 Phishing verificado vs 600 Legit Mixtas]
        D[Cohorte D: Subgrupos Estructurales<br>Con rutas: N=570 vs Sin rutas: N=630<br>Desglose por fuente: PT, OP, CISA, HIPO, TR, MJ]
    end
```

### 2.1. Cohorte A (Línea Base Histórica, $N=1,200$)
- **Composición:** 297 URLhaus, 260 PhishTank, 43 OpenPhish, 389 Tranco, 211 Majestic.
- **Propósito:** Replicar exactamente la evaluación reportada en versiones previas del manuscrito y servir de referencia para los deltas de desempeño.
- **Prevalencia:** $50.0\%$ maliciosas / $50.0\%$ legítimas.

### 2.2. Cohorte B (Aislamiento de Malware, $N=903$)
- **Composición:** 260 PhishTank, 43 OpenPhish, 389 Tranco, 211 Majestic.
- **Propósito:** Medir el desempeño sobre la cohorte histórica cuando se elimina el atajo sintáctico de URLhaus sin alterar las muestras benignas.
- **Prevalencia:** $33.55\%$ phishing / $66.45\%$ legítimas.
- **Advertencia Metodológica:** Al reducirse la prevalencia de positivos, el valor de $F_1$ no es directamente comparable de manera causal con la Cohorte A; debe analizarse en conjunto con Precision, Recall y FPR.

### 2.3. Cohorte C (Especializada de Phishing y Balanceada, $N=1,200$)
- **Composición:**
  - 600 `PHISHING_VERIFICADO`: 260 PhishTank históricos + 43 OpenPhish históricos + 297 nuevos casos de PhishTank con target institucional verificado (e.g., Microsoft, PayPal, Allegro).
  - 600 `LEGITIMO_VERIFICADO`: 195 Tranco bare + 105 Majestic bare + 150 CISA `.gov` con rutas + 150 HIPO `.edu` con rutas.
- **Propósito:** Evaluación definitiva para publicación: tamaño idéntico a la histórica ($N=1,200$), prevalencia balanceada ($50.0\%$), libre de atajos de malware y con simetría en la distribución de rutas.

### 2.4. Cohorte D (Análisis de Sensibilidad de Subgrupos)
- Subconjunto con rutas funcionales ($n=570$).
- Subconjunto de dominios raíz o bare domains ($n=630$).
- Evaluaciones estratificadas por proveedor de origen.

---

## 3. Modelos Evaluados y Parámetros Congelados

Se auditaron y evaluaron tres variantes de modelos pre-entrenados sin modificar sus pesos ni sus hiperparámetros:

1. **$M_0$ Léxico Original (`artifacts/url-baseline-0.2.0/model.joblib`):**
   - Clasificador: LightGBM (`LGBMClassifier`).
   - Perfil de características: `authority_only` (11 características léxicas: longitud de URL, entropía, recuento de dígitos, recuento de subdominios, recuento de etiquetas de host, longitud de ruta, longitud de host, ratios de caracteres, etc.).
   - Umbral de decisión operativo: $\tau = 0.519047$ (calibrado originalmente para baja tasa de falsos positivos en el conjunto de validación).
   - Nota de implementación: Conserva la heurística previa donde las etiquetas `www.` no eran retiradas en el cálculo de subdominios.

2. **$M_0$ Léxico Normalizado:**
   - Idéntica arquitectura y pesos que $M_0$ Original, pero aplicando el extractor formal `UrlFeatureContext` con `_strip_www()`, asegurando que `www.example.com` no compute un subdominio artificial espurio.
   - Umbral: $\tau = 0.519047$.

3. **Modelo Híbrido $M_0+\text{Brand}+\text{Rules}$ (Configuración C):**
   - Integración multi-etapa:
     $$\text{P}_{\text{final}} = f(P_{M_0}, \text{Reputación}(\text{Tranco Top 1M}), \text{SimilitudMarca}, \text{ReglasSemánticas})$$
   - Si el dominio registrado pertenece al Tranco Top 1M con puntuación de confianza alta ($\text{trust\_score} \ge 0.85$) y no corresponde a un proveedor de hosting gratuito de usuarios, la sospecha de suplantación de marca y anomalías sintácticas se neutralizan.
   - Si se detecta un patrón de alta señal (e.g., typosquatting sobre marcas bancarias, discrepancia entre TLD nacional y entidad financiera), se inyecta un incremento ponderado en la probabilidad de phishing.
   - Umbral de decisión: $\tau = 0.5000$.

---

## 4. Métricas de Desempeño y Validación Estadística

### 4.1. Definición Formal de Métricas
Para cada modelo y cohorte se computan:
- **Verdaderos Positivos ($TP$), Verdaderos Negativos ($TN$), Falsos Positivos ($FP$), Falsos Negativos ($FN$)**.
- **Accuracy:** $\frac{TP + TN}{N}$
- **Precision:** $\frac{TP}{TP + FP}$
- **Recall (Sensibilidad):** $\frac{TP}{TP + FN}$
- **$F_1$-Score:** $\frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
- **False Positive Rate (FPR):** $\frac{FP}{FP + TN}$
- **Área bajo la Curva ROC (ROC-AUC):** Calculada sobre las probabilidades continuas $P \in [0, 1]$.

### 4.2. Estimación de Intervalos de Confianza (Bootstrap No Paramétrico)
Para cuantificar la variabilidad muestral sin asumir normalidad asintótica:
- Se ejecutaron $B = 1,000$ remuestreos con reemplazo para cada métrica clave ($F_1$, Precision, Recall, FPR, ROC-AUC).
- Se computaron los intervalos de confianza al 95% mediante el método de los percentiles ($2.5\%$ y $97.5\%$):
  $$\text{IC}_{95\%} = \left[ Q^*_{0.025}, \, Q^*_{0.975} \right]$$
- Si una métrica no admite cálculo en un subgrupo monofuente (e.g., cuando la clase negativa tiene tamaño cero en un feed de solo phishing), el valor se declara explícitamente como no aplicable (`None`), evitando inventar valores o divisiones por cero.

---

## 5. Garantías de Reproducibilidad e Integridad Científica

1. **Determinismo:** Semilla pseudoaleatoria fija (`SEED = 42`) para todas las rutinas de partición y bootstrap.
2. **Aislamiento Total de Dominios:** Verificación automatizada con scripts que aseguran que el 100% de los dominios de la Cohorte C son ajenos al corpus histórico de entrenamiento.
3. **Inmutabilidad de la Cohorte Histórica:** `cohort2_dataset.csv` se conserva íntegro en su ubicación original de control de versiones.
4. **Verificación Automatizada:** Suite de pruebas unitarias (`test_external_cohort_quality.py`) ejecutable con `pytest` que valida la consistencia matemática y estructural antes de la publicación de resultados.
