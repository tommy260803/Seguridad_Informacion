# Metodología Detallada del Experimento: Comparación Estadística y Ablaciones
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Protocolo de Ejecución — Fase 5: Inferencia Estadística, Baselines y Estudios de Ablación*

---

## 1. Flujo de Ejecución y Trazabilidad de Datos

El pipeline experimental se implementó en el script determinista [`run_statistical_comparison.py`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/run_statistical_comparison.py), ejecutado bajo semilla aleatoria fija `RNG = np.random.default_rng(20261015)`.

El proceso consta de seis fases secuenciales:

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. CARGA DE PREDICCIONES PAREADAS                                      │
│    - Partición host_unseen de prueba (N=691 URLs, 191 phish / 500 leg) │
│    - Predicciones y probabilidades: p_m0, p_m1, p_m2, p_m3             │
│    - Trazas de etapas históricas y etiquetas verdaderas                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ 2. CONSTRUCCIÓN Y EVALUACIÓN DE BASELINES A - F                        │
│    - Baseline A: M0 Léxico fijo (tau = 0.3827)                         │
│    - Baseline B: M1 Infraestructura fijo (tau = 0.5250)                │
│    - Baseline C: M2 Monolítico DOM completo (tau = 0.3950)             │
│    - Baseline D: Cascada Original Simétrica (H_esc <= 0.15)            │
│    - Baseline E: Cascada con Margen Simple (|p - 0.5| >= 0.40)         │
│    - Baseline F1: Cascada Asimétrica (Política C, p0 <= 0.005)         │
│    - Baseline F2: Cascada Selectiva con Abstención (Política D)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ 3. ESTUDIOS DE ABLACIÓN CONTROLADOS (ABL-01 a ABL-06)                  │
│    - ABL-01: Supresión de salida temprana (M2 vs Cascada D)            │
│    - ABL-02: Supresión de abstención (Forzada vs Rechazo)              │
│    - ABL-03: Umbral ingenuo 0.50 vs Umbral calibrado (M0 y M2)         │
│    - ABL-04: Restricción asimétrica en benignos tempranos (B vs C)     │
│    - ABL-05: Omisión de modalidades (M0 -> M1 -> M2)                   │
│    - ABL-06: Shannon Entropy vs Margen de Probabilidad Lineal          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ 4. ANÁLISIS DE CALIBRACIÓN PROBABILÍSTICA (ECE, MCE, Brier)            │
│    - 10 intervalos equiprobables / equiespaciados                      │
│    - Diagrama de fiabilidad y cómputo de fiabilidad por decil          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ 5. PRUEBAS INFERENCIALES Y AJUSTE DE COMPARACIONES MÚLTIPLES           │
│    - Remuestreo Bootstrap pareado (B = 2,000 réplicas por contraste)   │
│    - Test Exacto de McNemar (Binomial bilateral sobre discordantes)    │
│    - Control Benjamini-Hochberg FDR (q = 0.05) y Bonferroni            │
│    - Prueba Formal de No-Inferioridad (Margen delta = 0.02)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ 6. ANÁLISIS DE SENSIBILIDAD Y BARRIDO DE PARÁMETROS                    │
│    - Barrido de umbral H_esc en [0.02, 0.45] (15 puntos)               │
│    - Evaluación de curva de Pareto F1 vs Adquisiciones Evitadas        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Definición Algorítmica de Procedimientos Estadísticos

### 2.1. Remuestreo Bootstrap Pareado de Diferencias ($\Delta F_1$)
Dadas dos políticas $A$ y $B$ con predicciones binarias $\hat{\mathbf{y}}_A, \hat{\mathbf{y}}_B \in \{0, 1\}^N$ sobre las mismas $N=691$ observaciones con etiquetas verdaderas $\mathbf{y} \in \{0, 1\}^N$:
1. Para cada réplica $b = 1, \dots, B$ ($B=2,000$):
   a. Se genera un vector de índices aleatorios $\mathbf{idx}^{(b)}$ de longitud $N$ mediante muestreo con reemplazo.
   b. Se extraen los subconjuntos $\mathbf{y}^{(b)} = \mathbf{y}[\mathbf{idx}^{(b)}]$, $\hat{\mathbf{y}}_A^{(b)} = \hat{\mathbf{y}}_A[\mathbf{idx}^{(b)}]$, $\hat{\mathbf{y}}_B^{(b)} = \hat{\mathbf{y}}_B[\mathbf{idx}^{(b)}]$.
   c. Se calculan las métricas pareadas:
      $$F_{1, A}^{(b)} = \text{F1}(\mathbf{y}^{(b)}, \hat{\mathbf{y}}_A^{(b)}), \quad F_{1, B}^{(b)} = \text{F1}(\mathbf{y}^{(b)}, \hat{\mathbf{y}}_B^{(b)})$$
   d. Se registra la diferencia pareada:
      $$\Delta F_1^{(b)} = F_{1, A}^{(b)} - F_{1, B}^{(b)}$$
2. Se calculan los percentiles empíricos al $2.5\%$ y $97.5\%$ para el intervalo de confianza bilateral del $95\%$, y el percentil $2.5\%$ para el límite inferior unilateral del $97.5\%$.
3. El valor $p$ empírico se calcula mediante:
   $$p_{\text{boot}} = 2 \cdot \min\left( \frac{1}{B} \sum_{b=1}^{B} \mathbb{I}(\Delta F_1^{(b)} \le 0), \frac{1}{B} \sum_{b=1}^{B} \mathbb{I}(\Delta F_1^{(b)} \ge 0) \right)$$

### 2.2. Error de Calibración Esperado (ECE)
Se divide el espacio de probabilidades $[0, 1]$ en $M = 10$ intervalos $B_m = (\frac{m-1}{M}, \frac{m}{M}]$. Para cada intervalo:
- $\text{acc}(B_m) = \frac{1}{|B_m|} \sum_{i \in B_m} y_i$ (proporción real de casos positivos).
- $\text{conf}(B_m) = \frac{1}{|B_m|} \sum_{i \in B_m} p_i$ (probabilidad promedio predicha).
El error de calibración esperado se define como el promedio ponderado del error absoluto:
$$\text{ECE} = \sum_{m=1}^{M} \frac{|B_m|}{N} |\text{acc}(B_m) - \text{conf}(B_m)|$$

---
*Fin del documento de metodología experimental — Fase 5: Comparación Estadística y Estudios de Ablación.*
