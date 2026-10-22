# Diseño Experimental y Marco Metodológico Inferencial (Fase 5)
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Metodología Científica — Fase 5: Comparación Estadística, Estudios de Ablación e Inferencia Formal*

---

## 1. Justificación y Planteamiento del Problema

En la investigación aplicada de aprendizaje automático para la detección de phishing web, es frecuente encontrar evaluaciones que afirman la superioridad de arquitecturas complejas (multimodales, cascadas adaptativas o mecanismos de abstención) basándose únicamente en diferencias numéricas pequeñas y no respaldadas por pruebas de hipótesis formalmente estructuradas.

El propósito de este diseño experimental es aislar cuantitativamente la contribución causal de cada componente del sistema **PhishPe**, contrastándolos contra líneas base homogéneas (*baselines*) mediante comparaciones estrictamente pareadas y pruebas no paramétricas con control de la tasa de falsos descubrimientos (*False Discovery Rate*, FDR).

---

## 2. Variables Experimentales y Protocolo de Control

### 2.1. Variables Independientes (Factores Manipulados)
1. **Arquitectura de Inferencia:** Monolítica de etapa fija ($M_0, M_1, M_2, M_3$) vs. Cascada progresiva adaptativa ($M_4$) vs. Cascada con margen lineal simple.
2. **Criterio de Salida Temprana:** Simétrico informacional (Entropía de Shannon $H(p) \le 0.15$) vs. Asimétrico conservador ($p_0 \le 0.005$ para clase legítima).
3. **Mecanismo de Decisión:** Decisión forzada binaria (cobertura 100%) vs. Clasificación selectiva con abstención ($M_5$, derivación a SOC).
4. **Umbral Operativo de Decisión:** Calibrado en partición de validación ($\tau^* \in [0.38, 0.52]$) vs. Umbral ingenuo estándar ($\tau = 0.50$).
5. **Modalidades Sensoriales Disponibles:** URL léxica ($M_0$), Infraestructura de red DNS/TLS ($M_1$), Árbol DOM HTML ($M_2$) y Renderizado visual Chrome CDP ($M_3$).

### 2.2. Variables Dependientes (Respuestas Cuantitativas)
- **Eficacia Predictiva:** F1-score, Precisión, Recall, Tasa de Falsos Positivos ($\text{FPR}$), Tasa de Falsos Negativos ($\text{FNR}$) y Área bajo la Curva ROC ($\text{ROC-AUC}$).
- **Eficiencia y Coste:** Número medio de modalidades requeridas ($N_{\text{mod}}$), Porcentaje de adquisiciones de HTML evitadas ($\%$) y Latencia mediana de pared ($P_{50}$).
- **Fiabilidad Probabilística:** Error de Calibración Esperado ($\text{ECE}$), Error Máximo de Calibración ($\text{MCE}$) y Puntuación de Brier ($\text{Brier}$).
- **Cobertura Operativa:** Porcentaje de transacciones decididas autónomamente vs. transacciones derivadas a triaje humano.

---

## 3. Hipótesis Científicas y Pruebas Estadísticas

### 3.1. Prueba de No-Inferioridad de la Cascada frente al Modelo Monolítico Completo ($M_2$)
- **Contexto:** La cascada ahorra más del 70% de las descargas HTML. Para ser admisible en producción, no debe sufrir una degradación inaceptable de rendimiento predictivo respecto a evaluar $M_2$ en todas las muestras.
- **Margen Pre-Definido de No-Inferioridad:** $\delta = 0.02$ (tolerancia máxima de pérdida de 2 puntos porcentuales de F1-score).
- **Hipótesis Formales:**
  $$H_0: F_{1, \text{cascada}} - F_{1, M2} \le -\delta \quad \text{vs.} \quad H_1: F_{1, \text{cascada}} - F_{1, M2} > -\delta$$
- **Criterio de Decisión:** Se rechaza $H_0$ si el límite inferior del intervalo de confianza al 97.5% unilateral (equivalente al 95% bilateral) para $\Delta F_1$, obtenido mediante remuestreo bootstrap con $B = 2,000$ réplicas, satisface:
  $$\text{IC}_{97.5\%, \text{inferior}}(\Delta F_1) > -0.02$$

### 3.2. Comparaciones Pareadas de Discordancia Binaria (Test Exacto de McNemar)
Para pares de políticas evaluadas sobre la misma partición *host_unseen* ($N=691$), se construye la tabla de contingencia $2 \times 2$ de respuestas correctas e incorrectas:
- $b$: Casos donde la Política A acierta y la Política B falla.
- $c$: Casos donde la Política A falla y la Política B acierta.
- **Hipótesis Nula:** $H_0: P(\text{A acierta, B falla}) = P(\text{A falla, B acierta}) \iff b \sim \text{Binomial}(b + c, 0.5)$.
- Se aplica la prueba binomial exacta bilateral con corrección de continuidad de Edwards.

### 3.3. Control de Tasa de Descubrimientos Falsos (Benjamini-Hochberg FDR)
Dado que se contrastan múltiples hipótesis de forma simultánea, se aplica el procedimiento de corrección de Benjamini-Hochberg (BH) con un umbral nominal de $\alpha = 0.05$ y la corrección conservadora de Bonferroni:
$$P_{(k)} \le \frac{k}{m} \cdot Q, \quad \text{donde } m = 7 \text{ contrastes y } Q = 0.05$$

---

## 4. Cohortes y Particiones Utilizadas

1. **Partición de Prueba Independiente *Host-Unseen* ($N=691$):** Conjunto estrictamente congelado de evaluación, con separación completa de dominios respecto al entrenamiento y validación ($N_{\text{phish}}=191, N_{\text{legit}}=500$). Utilizado para las comparaciones pareadas de Baselines A-F, estudios de ablación 1-6 y análisis de calibración.
2. **Subconjunto Visual Auténtico ($N=83$):** URLs pertenecientes a *host_unseen* con telemetría de navegador Headless Chrome CDP 100% verificada, utilizado para comparar el coste marginal de $M_3$.
3. **Cohorte Externa de Validación ($N=1,200$):** Verificación de generalización entre dominios y ausencia de sobreajuste.

---
*Fin del documento de diseño experimental — Fase 5: Comparación Estadística y Ablaciones.*
