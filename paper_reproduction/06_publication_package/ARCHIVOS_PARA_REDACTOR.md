# Guía de Redacción Académica y Mapeo de Archivos para el Redactor
**Destino de Publicación:** *Revista Politécnica* (Escuela Politécnica Nacional, Ecuador)  
**Proyecto:** PhishPe / PhishGuard Pro  
**Audiencia de este Documento:** Investigador / Redactor Académico encargado de actualizar el manuscrito  
**Fecha:** Octubre 2026  

---

## 1. Bienvenida e Instrucciones Generales

Estimado redactor académico:

Este paquete de evidencias ha sido diseñado para proporcionarle **toda la información cuantitativa, metodológica, visual y estadística necesaria para redactar y defender con éxito el artículo de PhishPe ante los revisores de Revista Politécnica**.

**Regla de Oro:**  
Usted **NO necesita calcular ni estimar ninguna cifra**. Todos los valores reportados en este paquete han sido verificados y recalculados contra código fuente determinista y datos empíricos congelados. Para garantizar la coherencia del manuscrito, utilice exclusivamente las tablas, figuras y lineamientos descritos a continuación.

---

## 2. Mapa Rápido de Archivos por Función

```text
paper_reproduction/06_publication_package/
│
├── 📖 GUÍAS METODOLÓGICAS Y TEXTUALES:
│   ├── AFIRMACIONES_PERMITIDAS_Y_PROHIBIDAS.md  <-- ¡LECTURA OBLIGATORIA! Qué decir y qué NO decir
│   ├── CAMBIOS_RESPECTO_ARTICULO_ACTUAL.md      <-- Tabla comparativa: versión anterior vs nueva versión
│   ├── METODOLOGIA_CONSOLIDADA.md               <-- Redacción formal de la metodología (splits, fórmulas, cascada)
│   ├── RESULTADOS_CONSOLIDADOS.md               <-- Resumen ejecutivo de métricas para Results & Discussion
│   ├── HALLAZGOS_CIENTIFICOS.md                 <-- Los 4 descubrimientos clave para Abstract y Conclusiones
│   ├── LIMITACIONES_CONSOLIDADAS.md             <-- Texto listo para la subsección de Limitaciones y Validez
│   ├── INVENTARIO_FIGURAS_TABLAS.md             <-- Catálogo detallado de cada tabla y figura con su pie de foto
│   ├── README_REPRODUCCION.md                   <-- Para incluir como anexo o enlace al repositorio de datos
│   └── ESTADO_FINAL_REPOSITORIO.md              <-- Certificación de integridad de código y hashes
│
├── 📊 TABLAS MAESTRAS PARA EL MANUSCRITO (Formato CSV en tables/):
│   ├── master_datasets_and_splits.csv          --> [Tabla 1 en el Paper] Datasets, tamaños, balance
│   ├── master_classifier_performance.csv       --> [Tabla 2 en el Paper] Desempeño M0, M1, M2, M3, M4, M5
│   ├── master_external_generalization.csv      --> [Tabla 3 en el Paper] Resultados por fuente externa
│   ├── master_early_exit_policies.csv          --> [Tabla 4 en el Paper] Comparativa de las 5 políticas de cascada
│   ├── master_abstention_selective.csv         --> [Tabla 5 en el Paper] Clasificación selectiva con abstención
│   ├── master_missing_modalities_fallback.csv  --> [Tabla 6 en el Paper] Comparativa de contingencias ante fallos
│   ├── master_systems_efficiency.csv           --> [Tabla 7 en el Paper] Benchmarking multinivel A, B y C
│   ├── master_ablations_and_comparisons.csv    --> [Tabla 8 en el Paper] Estudio de ablación ABL-01 a ABL-06
│   ├── master_inferential_statistics.csv       --> [Tabla 9 en el Paper] Pruebas McNemar, Wilcoxon, No-inferioridad
│   └── master_operational_validation.csv       --> [Tabla 10 en el Paper] Rendimiento API, RAM y arranque
│
├── 📈 FIGURAS DE ALTA RESOLUCIÓN (Formato PNG 300 DPI en figures/):
│   ├── fig_non_inferiority_forest_plot.png     --> [Figura Clave] No-inferioridad Cascada vs M2 Monolítico
│   ├── fig_f1_vs_latency_pareto.png            --> [Figura Clave] Frontera de Pareto F1 vs Latencia (ms)
│   ├── fig_ablation_tornado_chart.png          --> [Figura Clave] Diagrama de tornado del estudio de ablación
│   ├── fig_availability_by_class_and_source.png--> [Figura Clave] Evidencia empírica del sesgo MNAR
│   ├── fig_fallback_strategies_tradeoff.png    --> Trade-off de precisión vs recall en fallback
│   ├── fig_complete_case_vs_ite_performance.png--> Demostración del sesgo de casos completos
│   ├── fig_stage_stopping_distribution.png     --> Distribución de detención de URLs por etapa
│   ├── fig_threshold_sensitivity_sweep.png     --> Sensibilidad de umbrales en cascada
│   ├── fig_risk_coverage_curve.png             --> Curva riesgo vs cobertura en abstención
│   ├── fig_calibration_curves.png              --> Curvas de calibración y diagramas de confiabilidad
│   ├── fig_bootstrap_diff_distributions.png    --> Distribuciones bootstrap de diferencias de F1
│   ├── fig_baseline_f1_vs_cost.png             --> F1 vs costo computacional frente a baselines
│   └── fig_latency_by_policy.png               --> Latencia empírica por política de cascada
│
└── 🔍 TRAZABILIDAD Y EVIDENCIAS:
    ├── MATRIZ_TRAZABILIDAD_PUBLICACION.csv      <-- Mapeo 1:1 de cada afirmación y dato a su script fuente
    ├── data_manifests/                         <-- Manifiestos de URLs, auditoría de dominios y hardware
    └── statistics/                             <-- 16 archivos CSV con resultados estadísticos intermedios
```

---

## 3. Guía de Redacción Sección por Sección para *Revista Politécnica*

### 3.1. Título y Resumen (Abstract)
- **Título Sugerido:** *Detección Progresiva y Multimodal de Phishing Web con Cascadas Adaptativas Asimétricas, Clasificación Selectiva y Validación bajo Datos Faltantes*.
- **Cifras Clave a incluir en el Resumen:**
  - $F_1$-score de la cascada: $0.9281$.
  - Ahorro de adquisiciones costosas (HTML DOM): $67.87\%$.
  - Reducción de latencia: Factor de $3\times$ respecto al procesamiento monolítico ($122 \text{ ms}$ vs $378 \text{ ms}$).
  - Aporte de infraestructura ($M_1$): $\Delta F_1 = +0.0594$ ($p < 0.001$, McNemar), reduciendo el FPR en un $81.3\%$.
  - Robustez ante sitios caídos (MNAR): Fallback léxico preserva $93.64\%$ de precisión sobre $N=600$ casos reales.
  - Clasificación selectiva ($M_5$): $F_1$ efectivo de $0.9812$ con riesgo selectivo de solo $1.20\%$ bajo cobertura del $92.4\%$.

### 3.2. Introducción y Motivación
- **Enfoque:** Resaltar el dilema operativo de los navegadores web: los clasificadores basados únicamente en URL sufren falsos positivos, pero los modelos multimodales completos son prohibitivamente lentos para el camino crítico de navegación e inútiles cuando los sitios maliciosos ya han sido dados de baja.
- **Consultar:** `HALLAZGOS_CIENTIFICOS.md` y `METODOLOGIA_CONSOLIDADA.md`.

### 3.3. Metodología y Arquitectura Progresiva
- **Estructura Recomendada:**
  1. *Etapas Progresivas:* Definición formal de $M_0$ (Léxico), $M_1$ (Infraestructura DNS/SSL), $M_2$ (HTML DOM) y $M_3$ (Visual).
  2. *Política de Cascada Asimétrica (Política C):* Explicar el riesgo de la evasión en plataformas legítimas (Google Sites, Firebase) y justificar matemáticamente la **Guarda Asimétrica** ($p_0 \le 0.005$ para salida temprana benigna).
  3. *Clasificación Selectiva con Abstención ($M_5$):* Explicar el mecanismo de rechazo basado en umbrales de certidumbre para alertas críticas.
- **Tablas/Figuras a enlazar:** Tabla 1 (`master_datasets_and_splits.csv`), `fig_threshold_sensitivity_sweep.png`, `fig_stage_stopping_distribution.png`.

### 3.4. Resultados Experimentales y Comparativa
- **Estructura Recomendada:**
  1. *Desempeño de Modelos Base y Validación Externa:* Presentar la Tabla 2 y Tabla 3. Destacar que no existe fuga de información (0 dominios solapados).
  2. *Prueba Formal de No-Inferioridad:* Presentar la prueba con margen $\delta = 0.02$. Demostrar que el IC del 95% [$-0.0085, +0.0074$] garantiza que la cascada no es inferior a $M_2$ monolítico ($p < 0.001$), ahorrando a la vez el $67.87\%$ de descargas. Enlazar `fig_non_inferiority_forest_plot.png`.
  3. *Comparativa con Baselines:* Discutir la Tabla 8 y `fig_baseline_f1_vs_cost.png`.

### 3.5. Evaluación en Condiciones Reales: Modalidades Faltantes (MNAR)
- **Aspecto Novedoso del Paper:** La mayoría de la literatura asume que las páginas web siempre pueden descargarse. PhishPe es de los primeros artículos en demostrar empíricamente el sesgo MNAR en phishing (Fisher $p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$).
- **Demostración Crítica:**
  - Mostrar por qué la imputación por ceros (Estrategia B) es destructiva ($\text{FPR} = 18.67\%$).
  - Demostrar la superioridad de la Estrategia C (Fallback a $M_0$, Precisión $93.64\%$).
- **Tablas/Figuras a enlazar:** Tabla 6 (`master_missing_modalities_fallback.csv`), `fig_availability_by_class_and_source.png`, `fig_fallback_strategies_tradeoff.png`, `fig_complete_case_vs_ite_performance.png`.

### 3.6. Rendimiento de Sistemas y MLOps
- **Separación de Niveles A, B y C:**
  - Nivel A (CPU Algorítmico local): $M_0 = 0.18 \text{ ms}$.
  - Nivel B (I/O Red Externa): $M_1 = 375 \text{ ms}$; Captura Chrome CDP $= 2,166 \text{ ms}$.
  - Nivel C (API FastAPI Extremo a Extremo): $M_0 = 2.42 \text{ ms}$.
- **Conclusión de Arquitectura:** Chrome CDP es inviable para inspección interactiva síncrona; debe operar fuera de banda.
- **Tablas/Figuras a enlazar:** Tabla 7 (`master_systems_efficiency.csv`), Tabla 10 (`master_operational_validation.csv`), `fig_f1_vs_latency_pareto.png`, `fig_latency_by_policy.png`.

### 3.7. Estudio de Ablación e Inferencia Estadística
- **Jerarquía de Modalidades:** Citar el diagrama de tornado (`fig_ablation_tornado_chart.png`) y la Tabla 9.
  - La infraestructura es la modalidad determinante ($\Delta F_1 = -0.0594, p < 0.001$).
  - La guarda asimétrica evita 6 falsos negativos críticos ($\Delta F_1 = -0.0185$).
  - El contenido HTML DOM tiene un aporte marginal ($\Delta F_1 = -0.0063, p = 0.7905$).

### 3.8. Discusión, Limitaciones y Conclusiones
- **Limitaciones Obligatorias a Declarar:** Copiar fielmente los puntos de `LIMITACIONES_CONSOLIDADAS.md` (sesgo temporal de muestras, dominios benignos de rankings Tranco/Majestic, inviabilidad de CDP en cliente).
- **Verificación de Afirmaciones:** Antes de enviar a revisión, contrastar el texto contra `AFIRMACIONES_PERMITIDAS_Y_PROHIBIDAS.md`.

---

## 4. Convenciones de Formato para *Revista Politécnica*

1. **Notación Numérica:** Utilizar coma decimal en redacción en español (e.g., $F_1 = 0,9281$) o punto si la revista lo solicita en plantilla bilingüe. Mantener 4 cifras decimales para métricas de desempeño ($F_1$, Precisión, Recall) y 2 para porcentajes y tiempos en milisegundos.
2. **Reporte de Significancia:** Reportar siempre el estadístico de prueba, los grados de libertad (o tamaño muestral) y el $p$-valor exacto:
   - *Ejemplo correcto:* "$\chi^2(1) = 16,96, p = 1,0 \times 10^{-5}$" o "$p < 0,001$".
   - *Ejemplo incorrecto:* "el modelo fue mejor con $p = 0$".
3. **Hardware Utilizado:** Citar el procesador exacto del banco de pruebas (Intel Core i5-13600K, 32 GB RAM DDR5) para evitar objeciones de reproducibilidad en benchmarks.
4. **Disponibilidad de Datos y Código:** Incluir en la sección de disponibilidad el enlace al repositorio público GitHub con el tag de la versión auditada.
