# Inventario Maestro de Tablas y Figuras para Publicación
**Sistema:** PhishPe / PhishGuard Pro  
**Destino:** *Revista Politécnica* (Ecuador)  
**Total Artefactos:** 10 Tablas Maestras CSV | 18 Figuras de Publicación PNG  
**Fecha de Consolidación:** Octubre 2026  

---

## 1. Inventario de Tablas Maestras Consolidadas

Todas las tablas maestras están ubicadas en `paper_reproduction/06_publication_package/tables/` en formato CSV normalizado con cabeceras explícitas y precisión numérica uniforme.

| Tabla | Nombre del Archivo CSV | Sección Sugerida en Manuscrito | Descripción / Mensaje Científico | Script / Origen de Datos |
|:---:|:---|:---|:---|:---|
| **Tabla 1** | `master_datasets_and_splits.csv` | **Metodología: Datasets** | Inventario exhaustivo de particiones (Train, Val, Test interno, Cohorte externa $N=1200$, Cascada $N=691$, Sondeo en vivo $N=600$), balance de clases y fuentes. | `reproducibility/consolidate_master_tables.py` |
| **Tabla 2** | `master_classifier_performance.csv` | **Resultados: Modelos Base** | Comparativa de rendimiento canónico de clasificadores aislados ($M_0$ Léxico, $M_1$ Infraestructura, $M_2$ HTML DOM, $M_3$ Visual, $M_4$ Cascada, $M_5$ Abstención) con $F_1$, Precisión, Recall, FPR, ROC-AUC y ECE. | `statistics/05_master_classifier_performance.csv` |
| **Tabla 3** | `master_external_generalization.csv` | **Resultados: Validación Externa** | Generalización en cohorte externa $N=1200$ desglosada por fuente (PhishTank, OpenPhish, URLhaus malware, Tranco, Majestic) y cohorte limpia auditada. Demuestra 0 solapamiento de dominios. | `statistics/01_external_validation_by_source.csv` |
| **Tabla 4** | `master_early_exit_policies.csv` | **Resultados: Cascadas Adaptativas** | Evaluación rigurosa de 5 políticas de salida temprana ($N=691$): conservadora, agresiva, balanceada, asimétrica (Política C con guarda $p_0 \le 0.005$) y oráculo. Ahorro de adquisiciones HTML vs falsos negativos. | `statistics/02_early_exit_policies_summary.csv` |
| **Tabla 5** | `master_abstention_selective.csv` | **Resultados: Clasificación Selectiva** | Desempeño del modelo con opción de rechazo ($M_5$): cobertura ($92.4\%$), riesgo selectivo ($1.2\%$) y $F_1$ efectivo sobre casos cubiertos ($0.9812$). | `statistics/02_abstention_thresholds.csv` |
| **Tabla 6** | `master_missing_modalities_fallback.csv` | **Resultados: Datos Faltantes (MNAR)** | Desempeño en sondeo en vivo ($N=600$) bajo 4 estrategias de contingencia: casos completos (Sesgo de Supervivencia), imputación por ceros (desastre: FPR $18.67\%$), fallback a $M_0$ (Estrategia C: Precisión $93.64\%$) y fallback adaptativo. | `statistics/03_fallback_strategies_metrics.csv` |
| **Tabla 7** | `master_systems_efficiency.csv` | **Rendimiento de Sistemas y MLOps** | Benchmark multinivel desacoplado: Nivel A (CPU algorítmico, $0.18 \text{ ms}$ en $M_0$), Nivel B (I/O Red/CDP, $375 \text{ ms}$ en $M_1$, $2166 \text{ ms}$ en captura visual) y Nivel C (API FastAPI e2e, $2.42 \text{ ms}$ en $M_0$). | `statistics/04_benchmark_levels_summary.csv` |
| **Tabla 8** | `master_ablations_and_comparisons.csv` | **Discusión: Ablación Experimental** | Estudio de ablación sistemática (ABL-01 a ABL-06): impacto de remover infraestructura, HTML, guarda asimétrica, calibración de probabilidades y abstención. | `statistics/05_master_ablation_study.csv` |
| **Tabla 9** | `master_inferential_statistics.csv` | **Resultados: Estadística Inferencial** | Pruebas de significancia: McNemar ($\chi^2 = 16.96, p = 1.0 \times 10^{-5}$ para $M_1$ vs $M_0$), Wilcoxon, prueba exacta de Fisher para MNAR ($p = 4.28 \times 10^{-46}$), ajuste Benjamini-Hochberg y prueba de No-Inferioridad ($\delta = 0.02$). | `statistics/05_inferential_tests_results.csv` |
| **Tabla 10** | `master_operational_validation.csv` | **Ingeniería de Software / Despliegue** | Métricas operativas de arranque en frío/caliente de FastAPI, consumo de memoria RAM por etapa y estabilidad de concurrencia bajo carga. | `statistics/04_system_resources_profile.csv` |

---

## 2. Inventario de Figuras de Publicación

Todas las figuras están disponibles en `paper_reproduction/06_publication_package/figures/` en formato PNG de alta resolución (300 DPI, listas para maquetación en LaTeX o Word).

```text
paper_reproduction/06_publication_package/figures/
├── fig_ablation_tornado_chart.png
├── fig_acquisition_failures_pareto.png
├── fig_availability_by_class_and_source.png
├── fig_baseline_f1_vs_cost.png
├── fig_bootstrap_diff_distributions.png
├── fig_calibration_curves.png
├── fig_complete_case_vs_ite_performance.png
├── fig_cumulative_cost_by_modality.png
├── fig_f1_vs_latency_pareto.png
├── fig_fallback_strategies_tradeoff.png
├── fig_latency_by_policy.png
├── fig_latency_distribution.png
├── fig_non_inferiority_forest_plot.png
├── fig_pareto_f1_vs_modalities.png
├── fig_risk_coverage_curve.png
├── fig_savings_by_case_complexity.png
├── fig_stage_stopping_distribution.png
└── fig_threshold_sensitivity_sweep.png
```

### Detalle Individual de Cada Figura

#### 1. `fig_non_inferiority_forest_plot.png`
- **Sección Sugerida:** Resultados: Comparativa de Cascada vs Monolítico
- **Leyenda Recomendada:** *Forest Plot de la prueba formal de no-inferioridad entre la cascada adaptativa (Política C) y el modelo monolítico completo $M_2$ ($\delta = 0.02$). El intervalo de confianza del 95% [$-0.0085, +0.0074$] no cruza el margen de inferioridad tolerado ($p < 0.001$).*
- **Mensaje Científico:** La cascada no degrada significativamente el poder predictivo mientras ahorra más del 67% de adquisiciones costosas.

#### 2. `fig_f1_vs_latency_pareto.png`
- **Sección Sugerida:** Rendimiento y Evaluación de Sistemas
- **Leyenda Recomendada:** *Frontera de Pareto entre desempeño predictivo ($F_1$-score) y latencia promedio por URL (ms en escala logarítmica). Se compara $M_0$, $M_1$, $M_2$, $M_3$ y las políticas de cascada adaptativa.*
- **Mensaje Científico:** La cascada adaptativa se posiciona en el punto óptimo de la curva de eficiencia, superando en latencia al modelo monolítico por un factor de $3\times$.

#### 3. `fig_ablation_tornado_chart.png`
- **Sección Sugerida:** Estudio de Ablación y Discusión
- **Leyenda Recomendada:** *Diagrama de tornado del estudio de ablación. Variación de $F_1$-score ($\Delta F_1$) al sustraer componentes clave: infraestructura ($\Delta F_1 = -0.0594$), guarda asimétrica ($\Delta F_1 = -0.0185$) y HTML ($\Delta F_1 = -0.0063$).*
- **Mensaje Científico:** La infraestructura de red es el componente individual más crítico; el contenido HTML aporta mejoras marginales no significativas.

#### 4. `fig_availability_by_class_and_source.png`
- **Sección Sugerida:** Evaluación en Condiciones Reales / Datos Faltantes
- **Leyenda Recomendada:** *Tasa de disponibilidad empírica de modalidades (URL, DNS/SSL, HTML DOM, Captura Visual) desglosada por clase (Phishing vs Benigno) y fuente en el sondeo en vivo ($N=600$).*
- **Mensaje Científico:** Evidencia gráfica del sesgo MNAR: mientras que las muestras benignas tienen un 95%+ de disponibilidad en todas las modalidades, el phishing colapsa al 13.3% en HTML y Visual debido a caídas de servicio.

#### 5. `fig_complete_case_vs_ite_performance.png`
- **Sección Sugerida:** Metodología y Sesgo de Supervivencia
- **Leyenda Recomendada:** *Comparativa de desempeño entre el análisis de casos completos ($N=247$, sesgo de supervivencia) y la evaluación Intention-to-Evaluate sobre la población total ($N=600$).*
- **Mensaje Científico:** Evaluar únicamente casos completos infla artificialmente las métricas reportadas y enmascara la necesidad urgente de políticas de fallback.

#### 6. `fig_fallback_strategies_tradeoff.png`
- **Sección Sugerida:** Evaluación de Mecanismos de Fallback
- **Leyenda Recomendada:** *Trade-off de precisión vs recall bajo cuatro estrategias de contingencia ante modalidades faltantes. La Estrategia C (fallback léxico a $M_0$) preserva la mayor precisión ($93.64\%$) evitando falsas alarmas masivas.*
- **Mensaje Científico:** La imputación de ceros colapsa; el fallback jerárquico es la solución matemáticamente óptima.

#### 7. `fig_acquisition_failures_pareto.png`
- **Sección Sugerida:** Análisis Forense y Disponibilidad Web
- **Leyenda Recomendada:** *Diagrama de Pareto de las causas raíz de falla en la adquisición de contenido web en sitios maliciosos: HTTP 404 (48.3%), NXDOMAIN (26.7%), Connection Timeout (15.0%) y SSL Handshake Error (10.0%).*
- **Mensaje Científico:** La naturaleza efímera del phishing es la causa dominante de fallas de red, no la lentitud del sistema extractor.

#### 8. `fig_stage_stopping_distribution.png`
- **Sección Sugerida:** Dinámica de la Cascada Adaptativa
- **Leyenda Recomendada:** *Distribución de detención de URLs por etapa en la Cascada Adaptativa Asimétrica ($N=691$). El $54.8\%$ de los casos benignos se resuelven en $M_0$, el $20.8\%$ en $M_1$ y solo el $24.4\%$ escala hasta $M_2$.*
- **Mensaje Científico:** La cascada evita la sobrecarga computacional en las tres cuartas partes del tráfico web analizado.

#### 9. `fig_threshold_sensitivity_sweep.png`
- **Sección Sugerida:** Calibración de Hiperparámetros de Cascada
- **Leyenda Recomendada:** *Barrido de sensibilidad de los umbrales de decisión temprana ($\theta_{\text{early\_benign}}, \theta_{\text{early\_phish}}$) evaluando el balance entre tasa de falsos negativos y porcentaje de consultas escaladas.*
- **Mensaje Científico:** Demuestra por qué se seleccionó el umbral asimétrico $p_0 \le 0.005$ para proteger contra evasiones tempranas.

#### 10. `fig_risk_coverage_curve.png`
- **Sección Sugerida:** Clasificación Selectiva con Abstención
- **Leyenda Recomendada:** *Curva de riesgo-cobertura del clasificador selectivo $M_5$. A medida que se incrementa el umbral de confianza y se permite abstención en casos limítrofes, el riesgo empírico decrece monotónicamente del 6.8% al 1.2%.*
- **Mensaje Científico:** La abstención permite garantizar alta fiabilidad para sistemas de alerta crítica en ciberseguridad.

#### 11. `fig_calibration_curves.png`
- **Sección Sugerida:** Calibración Probabilística de Modelos
- **Leyenda Recomendada:** *Diagramas de confiabilidad y curvas de calibración (Reliability Diagrams) para los modelos $M_0, M_1, M_2$ antes y después del escalamiento isotónico (ECE reducido de $0.084$ a $0.021$).*
- **Mensaje Científico:** Las probabilidades de salida de PhishPe están calibradas y representan fielmente la certidumbre estadística del sistema.

#### 12. `fig_bootstrap_diff_distributions.png`
- **Sección Sugerida:** Validación Estadística Inferencial
- **Leyenda Recomendada:** *Distribuciones empíricas de diferencias de $F_1$ obtenidas mediante bootstrapping estratificado (1,000 réplicas). Se evidencia la superioridad consistente de $M_1$ sobre $M_0$ y la equivalencia entre Cascada y $M_2$.*
- **Mensaje Científico:** La robustez estadística de los hallazgos es independiente de fluctuaciones muestrales aleatorias.

#### 13. `fig_baseline_f1_vs_cost.png`
- **Sección Sugerida:** Comparativa con Baselines
- **Leyenda Recomendada:** *$F_1$-score vs costo computacional ponderado frente a 7 modelos de referencia (Baselines A-F, Heurísticas y Monolíticos).*
- **Mensaje Científico:** PhishPe domina la curva de eficiencia frente a baselines estándar de la literatura.

#### 14. `fig_cumulative_cost_by_modality.png`
- **Sección Sugerida:** Análisis de Costo Computacional
- **Leyenda Recomendada:** *Costo computacional acumulado por URL conforme se incorporan modalidades progresivas ($M_0 \rightarrow M_1 \rightarrow M_2 \rightarrow M_3$).*
- **Mensaje Científico:** Ilustra visualmente el salto exponencial de costo que implica la captura visual con navegadores.

#### 15. `fig_latency_distribution.png`
- **Sección Sugerida:** Benchmarking de Rendimiento
- **Leyenda Recomendada:** *Histogramas y curvas de densidad empírica de latencia para cada etapa del pipeline (Nivel A: CPU algorítmico, Nivel B: I/O de red).*
- **Mensaje Científico:** El análisis léxico exhibe varianza nula y latencia sub-milisegundo; la red introduce distribuciones de cola larga.

#### 16. `fig_latency_by_policy.png`
- **Sección Sugerida:** Evaluación de Políticas de Cascada
- **Leyenda Recomendada:** *Comparativa de latencia media, percentil 90 y percentil 99 entre las políticas de cascada conservadora, balanceada, asimétrica y monolítica.*
- **Mensaje Científico:** La política asimétrica reduce la latencia en un 64% respecto al procesamiento monolítico.

#### 17. `fig_savings_by_case_complexity.png`
- **Sección Sugerida:** Desempeño Operativo
- **Leyenda Recomendada:** *Porcentaje de ahorro de ancho de banda y tiempo de cómputo en función de la complejidad del tráfico (URLs triviales vs altamente ofuscadas).*
- **Mensaje Científico:** En tráfico web representativo (mayoría de URLs legítimas), el sistema alcanza ahorros reales superiores al 70%.

#### 18. `fig_pareto_f1_vs_modalities.png`
- **Sección Sugerida:** Discusión de Eficiencia Multimodal
- **Leyenda Recomendada:** *Frontera de Pareto entre número de modalidades activadas y $F_1$-score alcanzado. Muestra la asíntota de rendimiento a partir de $M_1$.*
- **Mensaje Científico:** El beneficio marginal decreciente de sumar modalidades más allá de infraestructura de red.

---

## 3. Matriz de Asociación: Tablas y Figuras por Sección del Manuscrito

| Sección del Manuscrito en Revista Politécnica | Tablas Primarias Recomendadas | Figuras Clave Recomendadas |
|:---|:---:|:---:|
| **3. Metodología y Datasets** | Tabla 1 (`master_datasets_and_splits.csv`) | `fig_availability_by_class_and_source.png` |
| **4. Arquitectura Progresiva y Cascadas** | Tabla 4 (`master_early_exit_policies.csv`) | `fig_threshold_sensitivity_sweep.png`, `fig_stage_stopping_distribution.png` |
| **5. Clasificación Selectiva y Calibración** | Tabla 5 (`master_abstention_selective.csv`) | `fig_risk_coverage_curve.png`, `fig_calibration_curves.png` |
| **6. Resultados Experimentales y Baselines** | Tabla 2 (`master_classifier_performance.csv`), Tabla 3 (`master_external_generalization.csv`) | `fig_baseline_f1_vs_cost.png`, `fig_non_inferiority_forest_plot.png` |
| **7. Evaluación bajo Modalidades Faltantes** | Tabla 6 (`master_missing_modalities_fallback.csv`) | `fig_complete_case_vs_ite_performance.png`, `fig_fallback_strategies_tradeoff.png`, `fig_acquisition_failures_pareto.png` |
| **8. Rendimiento de Sistemas y Benchmarking** | Tabla 7 (`master_systems_efficiency.csv`), Tabla 10 (`master_operational_validation.csv`) | `fig_f1_vs_latency_pareto.png`, `fig_latency_by_policy.png`, `fig_cumulative_cost_by_modality.png` |
| **9. Estudio de Ablación e Inferencia Estadística** | Tabla 8 (`master_ablations_and_comparisons.csv`), Tabla 9 (`master_inferential_statistics.csv`) | `fig_ablation_tornado_chart.png`, `fig_bootstrap_diff_distributions.png`, `fig_pareto_f1_vs_modalities.png` |
