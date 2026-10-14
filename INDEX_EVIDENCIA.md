# Índice Maestro de Evidencia Experimental — PhishPe / PhishGuard (`PhishPe_Article_APA7.docx`)

> **Versión definitiva auditada** · Dataset canónico `0.1.0` · **176,201 muestras** · Commit `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
> Verificación automática: `python scripts/verify_audit_report_consistency.py` → **100 % de coincidencias** (59/59 comprobaciones).  
> Tests: `pytest -q` → **127 passed, 0 failed**.  
> ZIP actualizado: [`evidencia_phishpe_corregida_scopus.zip`](file:///d:/Proyects/Seguridad_Informacion/evidencia_phishpe_corregida_scopus.zip) · **145.93 MB · 755 archivos**

Este paquete reúne todos los resúmenes JSON/CSV, predicciones por muestra, máscaras de abstención, tiempos por etapa, manifiestos, configuraciones, scripts de evaluación y figuras originales que respaldan las tablas y figuras del artículo. Se han excluido credenciales (`.env`) y datos personales. El informe de auditoría científica definitivo es [`INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md`](file:///d:/Proyects/Seguridad_Informacion/INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md).

---

## 1. Vinculación Exacta de Tablas del Artículo con sus Archivos de Origen

> [!IMPORTANT]
> Todas las cifras de las tablas usan la cohorte **Host-Unseen Complete-Case (CC)**, partición `test` **N = 691** (500 legítimas, 191 phishing), excepto donde se indica explícitamente ITE (N = 1,500) o Corpus Completo.  
> El modelo canónico M3 (CC) usa **características visuales reconstruidas** (`recorded_dom_viewport`) para el 98.6 % de las capturas históricas. La evaluación 100 % auténtica con Chrome CDP usa **N = 83** muestras de prueba (sección E5).

| Tabla en `PhishPe_Article_APA7.docx` | Descripción | Archivos JSON/CSV de Origen (Resumen) | Archivos de Predicciones por Muestra, Abstención y Tiempos | Script Generador |
| :--- | :--- | :--- | :--- | :--- |
| **Table 1** | *Primary Performance Comparison on Host-Unseen Complete-Case Test Partition (N = 691)* · **M0 F1=0.8658, M1 F1=0.9252, M2 F1=0.9315, M3 F1=0.9286, M4 F1=0.9248, M5-Selectivo F1=0.9538 (N=662)** | `artifacts/corrected_audit/evaluation_summary_real.json` (clave `multimodal_cohort.host_unseen.complete_case`)<br>`artifacts/corrected_audit/evaluation_report_real.csv`<br>`artifacts/corrected_audit/latency_benchmark_real.json` | `artifacts/m0-real/predictions.csv`<br>`artifacts/m1-real/predictions.csv`<br>`artifacts/m2-real/predictions.csv`<br>`artifacts/m3-real/predictions.csv`<br>`artifacts/m4-fixed-real/predictions.csv`<br>`artifacts/m4-real/predictions.csv`<br>`artifacts/m5-real/predictions.csv` (columnas: `sample_id, partition, label, probability_phishing, predicted_label, abstained, stop_stage, total_latency_ms`) | `scripts/train_and_evaluate_all_real.py`<br>`scripts/benchmark_latency_and_systems.py` |
| **Table 2** | *Cross-Cohort Generalization: Complete-Case (N=691), Intention-to-Evaluate ITE (N=1,500) y Temporal (N=964)* | `artifacts/corrected_audit/evaluation_summary_real.json` (claves `host_unseen.complete_case`, `host_unseen.ite`, `temporal.ite`)<br>`data/processed/0.1.0/statistics.json` | `artifacts/m0-ite-real/predictions.csv`<br>`artifacts/m1-ite-real/predictions.csv`<br>`artifacts/m2-ite-real/predictions.csv`<br>`artifacts/m3-ite-real/predictions.csv` | `scripts/train_and_evaluate_all_real.py`<br>`scripts/create_temporal_split.py` |
| **Table 3** | *Service-Level Agreement (SLA) Profiles and End-to-End Latency Percentiles* · M0 P50=16.89 ms, M3 E2E P50=3,884 ms, M5 E2E P50=499.64 ms (7.77× speedup) | `artifacts/corrected_audit/latency_benchmark_real.json` (claves `sla_profiles`, `stages_local_cpu_ms`, `stages_end_to_end_measured_authentic_n83_ms`, `cascade_m5_authentic_n83_end_to_end_ms`) | `artifacts/m4-fixed-real/stage_stopping_distribution.json`<br>`artifacts/m4-real/stage_stopping_distribution.json`<br>`artifacts/m5-real/stage_stopping_distribution.json` | `scripts/benchmark_latency_and_systems.py` |
| **Table 4** | *Adversarial Evasion Recall Across Six Perturbation Families on Host-Unseen Phishing Test Set (N_phish = 191)* · M5 Silent Bypass ASR: url_evasion=43.75%, combined=63.07% | `artifacts/corrected_audit/robustness_evaluation_real.json`<br>`artifacts/corrected_audit/robustness_evaluation_real.csv` | `artifacts/m5-real/predictions.csv` | `scripts/evaluate_robustness_and_stats.py` |
| **Table 5** | *Paired Bootstrap (B=1,000) and Exact Binomial McNemar Tests with Holm-Bonferroni Correction* · M0↔M1 p=1.05e-05, M0↔M5(N=662) p=1.91e-06 | `artifacts/corrected_audit/statistical_comparisons_all.json`<br>`artifacts/corrected_audit/statistical_comparisons_all.csv` | `artifacts/m0-real/predictions.csv` a `artifacts/m5-real/predictions.csv` | `scripts/evaluate_robustness_and_stats.py` |
| **Sección 5 (Texto)** | *Benchmarks de Filtro Bloom (hit-rate 0.08% FPR), Caché LRU Zipf (92.30% hit-rate) y Agente LLM* · Histórico: `llama-3.1-8b-instant` (N=30/100). En vivo M5-abstained: `openai/gpt-oss-20b` (N=7/29), latencia P50=1,842.73 ms | `artifacts/corrected_audit/cache_bloom_benchmark.json`<br>`artifacts/corrected_audit/llm_evaluation_summary.json` | `artifacts/corrected_audit/llm_evaluation_results.json` (100 registros)<br>`artifacts/corrected_audit/llm_live_m5_abstained_results.json` (29 registros M5-abstained) | `scripts/benchmark_latency_and_systems.py`<br>`scripts/evaluate_llm.py` |

---

## 2. Vinculación Exacta de Figuras del Artículo con sus Archivos de Origen

| Figura en `PhishPe_Article_APA7.docx` | Archivo de Imagen (`.png` / `.pdf`) | Archivos de Datos de Origen | Script Generador |
| :--- | :--- | :--- | :--- |
| **Figure 1** (*Stage Stopping Distributions Across Cascade Architectures*) | `artifacts/figures/modality_distribution.png`<br>`artifacts/figures/modality_distribution.pdf` | `artifacts/m4-fixed-real/stage_stopping_distribution.json`<br>`artifacts/m4-real/stage_stopping_distribution.json`<br>`artifacts/m5-real/stage_stopping_distribution.json` | `scripts/generate_figures.py` |
| **Figure 2** (*ROC Curves Across M0–M5*) | `artifacts/figures/roc_curves.png`<br>`artifacts/figures/roc_curves.pdf` | `artifacts/m0-real/predictions.csv` a `artifacts/m5-real/predictions.csv` | `scripts/generate_figures.py` |
| **Figure 3** (*Precision-Recall Curves Across Classifier Configurations*) | `artifacts/figures/pr_curves.png`<br>`artifacts/figures/pr_curves.pdf` | `artifacts/m0-real/predictions.csv` a `artifacts/m5-real/predictions.csv` | `scripts/generate_figures.py` |
| **Figure 4** (*Platt Sigmoidal Calibration Reliability Diagrams*) | `artifacts/figures/calibration_curves.png`<br>`artifacts/figures/calibration_curves.pdf` | `artifacts/m0-real/predictions.csv` a `artifacts/m3-real/predictions.csv` | `scripts/generate_figures.py` |
| **Figure 5** (*Selective Risk-Coverage Curves Driven by Normalized Shannon Entropy*) | `artifacts/figures/coverage_risk_curve.png`<br>`artifacts/figures/coverage_risk_curve.pdf` | `artifacts/corrected_audit/coverage_risk_curves_real.csv` | `scripts/generate_figures.py` |
| **Figure 6** (*Accuracy-versus-Cost Pareto Frontier*) | `artifacts/figures/cost_vs_performance.png`<br>`artifacts/figures/cost_vs_performance.pdf` | `artifacts/corrected_audit/evaluation_summary_real.json`<br>`artifacts/corrected_audit/latency_benchmark_real.json` | `scripts/generate_figures.py` |
| **Figure 7** (*End-to-End Latency Percentiles Across Stages M0–M5*) | `artifacts/figures/latency_by_modality.png`<br>`artifacts/figures/latency_by_modality.pdf` | `artifacts/corrected_audit/latency_benchmark_real.json` | `scripts/generate_figures.py` |
| **Figure 8** (*Adversarial Recall Resilience Across Perturbation Families*) | `artifacts/figures/perturbation_degradation.png`<br>`artifacts/figures/perturbation_degradation.pdf` | `artifacts/corrected_audit/robustness_evaluation_real.json` | `scripts/generate_figures.py` |
| **Figure 9** (*Temporal Concept Drift Comparison: Host-Unseen vs Temporal Split*) | `artifacts/figures/temporal_degradation.png`<br>`artifacts/figures/temporal_degradation.pdf` | `artifacts/corrected_audit/evaluation_summary_real.json` | `scripts/generate_figures.py` |
| **Figure 10** (*Lexical Baseline M0 Feature Discriminative Power*) | `artifacts/figures/m0_feature_importance.png`<br>`artifacts/figures/m0_feature_importance.pdf` | `artifacts/m0-real/model.joblib` + `data/processed/0.1.0/samples.csv` | `scripts/generate_figures.py` |
| **Figuras Suplementarias LLM** | `artifacts/figures/llm_vs_ml.png` (`.pdf`)<br>`artifacts/figures/llm_distribution.png` (`.pdf`) | `artifacts/corrected_audit/llm_evaluation_results.json`<br>`artifacts/corrected_audit/llm_evaluation_summary.json` | `scripts/llm_figures.py` |

---

## 3. Inconsistencias Auditadas y su Estado Final

| ID | Observación | Estado |
| :--- | :--- | :---: |
| **R2-1** | Dataset: el informe anterior declaraba 88,347 muestras → el archivo `samples.csv` contiene **176,201** | **RESUELTA** |
| **R2-2** | F1 de M0–M3 no coincidían con `metrics.json` → recalculados desde `predictions.csv`: M0=0.8658, M1=0.9252, M2=0.9315, M3=0.9286 | **RESUELTA** |
| **R2-3** | 467 capturas CDP reales en JSONL pero solo 40 PNG conservados → diseño del script (guardó solo `idx < 40`), 430 PNG temporales eliminados tras extraer descriptores | **PARCIALMENTE RESUELTA** |
| **R2-4** | Informe anterior citaba `llama-3.3-70b-versatile` → modelos reales: `llama-3.1-8b-instant` (histórico N=30) y `openai/gpt-oss-20b` (en vivo N=7) | **RESUELTA** |
| **R2-5** | Hardware declarado incorrecto (AMD Ryzen) → hardware real: **13th Gen Intel(R) Core(TM) i5-13600K**, 14P/20L cores, 15.78 GB RAM, Win 11 10.0.26200 | **RESUELTA** |

---

## 4. Estructura del Archivo `evidencia_phishpe_corregida_scopus.zip` (145.93 MB · 755 archivos)

- **`INFORME_AUDITORIA_Y_TRAZABILIDAD_SCOPUS.md`**: Informe científico definitivo con 11 experimentos trazados, 5 inconsistencias resueltas y matriz de validación.
- **`GUIA_REDACCION_Y_AUDITORIA_ARTICULO_APA7.md`**: Guía de redacción con toda la metodología, umbrales, aclaraciones y advertencias para el redactor.
- **`INDEX_EVIDENCIA.md`**: Este documento índice.
- **`scripts/verify_audit_report_consistency.py`**: Script de verificación automática (59 comprobaciones, 100 % exitosas).
- **`pyproject.toml`** y **`requirements-lock.txt`**: Dependencias exactas del entorno.
- **`data/processed/0.1.0/`**: `manifest.json`, `statistics.json` (`sha256: 947350f0…`) y `splits/` (`conventional.csv`, `host_unseen.csv`, `temporal.csv`, `temporal_host_unseen.csv`).
- **`artifacts/analysis-results/`**: Los 5 archivos JSONL de modalidades + `visual-results-authentic-cdp.jsonl` (467 capturas `live_cdp`) y `visual-results-synthetic-dom-proxy.jsonl` (5,536 reconstrucciones PIL anotadas con `is_synthetic: true`).
- **`artifacts/original_audit_snapshot/`**: Resultados originales preservados sin modificar.
- **`artifacts/corrected_audit/`**: Todos los JSON/CSV corregidos y enriquecidos (`evaluation_summary_real.json`, `latency_benchmark_real.json`, `statistical_comparisons_all.json`, `robustness_evaluation_real.json`, `cache_bloom_benchmark.json`, `llm_evaluation_summary.json`, `m3_visual_audit_and_authentic_evaluation.json`, `extension_architecture_and_hybrid_evaluation.json`, `m3-authentic-cdp/`).
- **`artifacts/m0-real/` … `artifacts/m5-real/`** y **`artifacts/m0-ite-real/` … `artifacts/m3-ite-real/`**: Manifiestos, registros de características, métricas, distribuciones de parada y predicciones por muestra.
- **`artifacts/url-baseline-0.2.0/`**, **`artifacts/m0-temporal/`**, **`artifacts/m0-temporal-host-unseen/`**: M0 sobre corpus completo con particiones temporales.
- **`artifacts/evaluation/`**: Resúmenes globales y figuras CSV.
- **`artifacts/figures/`**: Todas las figuras en `.png`/`.pdf`.
- **`artifacts/authentic-cdp-screenshots/`**: 40 archivos PNG físicos reales (37 exitosos + 3 error).
- **`artifacts/screenshots/`** y **`artifacts/previews/`**: 91 PNG y 97 HTML del sandbox del worker.
- **`src/`**, **`scripts/`**, **`configs/`**, **`extension/`**, **`tests/`**: Código fuente completo (sin `.env`, caches ni `.pyc`).
