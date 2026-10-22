# Guía de Reproducción Científica — PhishPe / PhishGuard Pro
**Destino:** Paquete de Evidencias Científicas para *Revista Politécnica* (Ecuador)  
**Versión de Auditoría:** 2.0 (Post-Auditoría Integral y Consolidación)  
**Fecha:** Octubre 2026  
**Licencia de Código:** MIT  

---

## 1. Resumen Ejecutivo de Reproducibilidad

Este directorio contiene el paquete integral de reproducibilidad científica del sistema **PhishPe** (detector progresivo y multimodal de phishing web con cascada adaptativa y abstención selectiva).

Todas las cifras, tablas maestras, figuras vectoriales/PNG y matrices de confusión presentadas en el artículo académico han sido extraídas, re-evaluadas y verificadas contra datos congelados y código determinista. No se utiliza ninguna simulación sintética ni métrica no rastreable.

### Principales Artefactos Validados
1. **Cohorte Externa de Validación ($N=1,200$):** Protocolo estricto de phishing limpio auditado sin fuga de dominios con el conjunto de entrenamiento (0% solapamiento).
2. **Evaluación de Cascada Adaptativa ($N=691$):** 5 políticas de decisión evaluadas, análisis forense de 25 falsos negativos y diseño de guarda benigna asimétrica.
3. **Sondeo en Vivo y Mecanismo Fallback ($N=600$):** Caracterización de asociación extrema entre clase y disponibilidad (consistente con patrón MNAR / sesgo de supervivencia, Fisher $p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$) y preservación de robustez operativa con Estrategia C (fallback léxico $M_0$, precisión 93.64%).
4. **Benchmark de Rendimiento Multinivel:** Separación estricta entre cómputo algorítmico local (Nivel A: $0.18 \text{ ms}$ en $M_0$), latencia I/O de red (Nivel B: $375 \text{ ms}$ en $M_1$, $2,166 \text{ ms}$ en captura visual) y latencia extremo a extremo de API (Nivel C: $2.42 \text{ ms}$ en $M_0$).
5. **Inferencia Estadística Rigurosa:** Pruebas de McNemar, Wilcoxon Signed-Rank, corrección FDR Benjamini-Hochberg y análisis exploratorio de No-Inferioridad ($\delta = 0.02$, $p < 0.001$).

---

## 2. Requisitos de Entorno y Hardware

### Entorno de Software
- **Sistema Operativo:** Windows 10/11, Ubuntu 22.04 LTS o macOS 13+
- **Python:** 3.10, 3.11 o 3.12 (probado y certificado en Python 3.12.10)
- **Librerías Clave:**
  - `numpy >= 1.24.0`
  - `pandas >= 2.0.0`
  - `scikit-learn >= 1.3.0`
  - `scipy >= 1.11.0`
  - `matplotlib >= 3.8.0`
  - `seaborn >= 0.13.0`
  - `joblib >= 1.3.0`
  - `fastapi >= 0.100.0`
  - `pytest >= 7.4.0`

### Hardware de Referencia (Banco de Pruebas de Rendimiento)
- **Procesador:** Intel Core i5-13600K (14 núcleos, 20 hilos, hasta 5.1 GHz)
- **Memoria RAM:** 32 GB DDR5 5600 MHz
- **Almacenamiento:** NVMe SSD PCIe 4.0 (lectura secuencial > 5000 MB/s)
- **Conectividad:** Enlace de fibra simétrica 300 Mbps con latencia base a DNS de $12 \text{ ms}$

---

## 3. Estructura de Directorios del Paquete

```text
paper_reproduction/
├── 00_audit/                     # Fase 0: Auditoría de código, datos y modelos
├── 01_external_validation/       # Fase 1: Validación externa N=1200 y solapamiento
├── 02_early_exit/                # Fase 2: Cascadas adaptativas N=691 y forense FN
├── 03_missing_modalities/        # Fase 3: Sondeo en vivo N=600 y evaluación MNAR
├── 04_performance/               # Fase 4: Benchmark multinivel A/B/C y Chrome CDP
├── 05_statistical_comparison/    # Fase 5: Pruebas inferenciales, baselines y no-inferioridad
└── 06_publication_package/       # Fase 6: Consolidación final para Revista Politécnica
    ├── README_REPRODUCCION.md
    ├── METODOLOGIA_CONSOLIDADA.md
    ├── RESULTADOS_CONSOLIDADOS.md
    ├── HALLAZGOS_CIENTIFICOS.md
    ├── LIMITACIONES_CONSOLIDADAS.md
    ├── CAMBIOS_RESPECTO_ARTICULO_ACTUAL.md
    ├── AFIRMACIONES_PERMITIDAS_Y_PROHIBIDAS.md
    ├── INVENTARIO_FIGURAS_TABLAS.md
    ├── ESTADO_FINAL_REPOSITORIO.md
    ├── ARCHIVOS_PARA_REDACTOR.md
    ├── MATRIZ_TRAZABILIDAD_PUBLICACION.csv
    ├── tables/                   # 10 Tablas Maestras CSV consolidadas
    ├── figures/                  # 18 Figuras de publicación en alta resolución PNG
    ├── data_manifests/           # 6 Manifiestos de datos y hardware
    ├── statistics/               # 16 Tablas estadísticas detalladas por fase
    └── reproducibility/          # Scripts maestros de consolidación y verificación
        ├── consolidate_master_tables.py
        ├── reproduce_all.py
        └── test_publication_package.py
```

---

## 4. Instrucciones de Reproducción Paso a Paso

### 4.1. Configuración Inicial del Entorno

1. Clonar el repositorio y situarse en la raíz del proyecto:
   ```bash
   git clone https://github.com/tommy260803/Seguridad_Informacion.git
   cd Seguridad_Informacion
   ```

2. Crear y activar un entorno virtual:
   ```bash
   python -m venv venv
   # En Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # En Linux/macOS:
   source venv/bin/activate
   ```

3. Instalar las dependencias requeridas:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install pytest scipy scikit-learn matplotlib seaborn
   ```

---

### 4.2. Ejecución Fase por Fase

Si se desea verificar o regenerar individualmente los resultados de cada etapa:

#### Fase 1: Cohorte Externa y Verificación de Solapamiento
```bash
python paper_reproduction/01_external_validation/scripts/01_prepare_cohort.py
python paper_reproduction/01_external_validation/scripts/02_audit_domains.py
python paper_reproduction/01_external_validation/scripts/03_evaluate_external.py
```
*Salidas esperadas:* Manifiesto de $N=1,200$ URLs (`external_cohort_manifest.csv`), reporte de 0 dominios solapados (`domain_overlap_audit.csv`) y métricas por fuente.

#### Fase 2: Políticas de Cascada Adaptativa y Forense de FN
```bash
python paper_reproduction/02_early_exit/scripts/01_audit_cascade.py
python paper_reproduction/02_early_exit/scripts/02_simulate_policies.py
python paper_reproduction/02_early_exit/scripts/03_forensic_fn.py
```
*Salidas esperadas:* Comparativa de 5 políticas de salida temprana sobre $N=691$, identificación de 25 falsos negativos y calibración de la política C con guarda asimétrica.

#### Fase 3: Evaluación de Modalidades Faltantes y Sondeo en Vivo
```bash
python paper_reproduction/03_missing_modalities/scripts/01_audit_missing.py
python paper_reproduction/03_missing_modalities/scripts/02_evaluate_missing.py
```
*Salidas esperadas:* Demostración de sesgo MNAR (prueba de Fisher $p < 10^{-45}$), evaluación de estrategias de fallback A, B, C y D sobre $N=600$.

#### Fase 4: Benchmark de Rendimiento Multinivel
```bash
python paper_reproduction/04_performance/scripts/01_benchmark_levels.py
python paper_reproduction/04_performance/scripts/02_generate_figures.py
```
*Salidas esperadas:* Mediciones desacopladas de CPU (Nivel A), I/O de red (Nivel B) y API FastAPI (Nivel C), más análisis de captura con Chrome CDP.

#### Fase 5: Inferencia Estadística y Estudio de Ablación
```bash
python paper_reproduction/05_statistical_comparison/scripts/01_statistical_comparison.py
```
*Salidas esperadas:* 7 baselines de referencia, 8 ablaciones sistemáticas, pruebas de McNemar/Wilcoxon con ajuste Benjamini-Hochberg, ECE y prueba de no-inferioridad ($\delta = 0.02$).

---

### 4.3. Consolidación y Verificación con Un Solo Comando

Para ejecutar la verificación integral de integridad y re-generar las 10 tablas maestras:

```bash
python paper_reproduction/06_publication_package/reproducibility/reproduce_all.py
```

Para ejecutar la suite completa de pruebas unitarias y de aserción científica:

```bash
pytest paper_reproduction/
```

*Resultado esperado:* Todos los tests pasan exitosamente (`38+ passed in < 2.0s`).

---

## 5. Integridad Criptográfica de Archivos Clave

| Archivo | Tipo | Registros / Dimensiones | Propósito Científico |
|:---|:---:|:---:|:---|
| `data_manifests/external_cohort_manifest.csv` | CSV | 1,200 URLs | Cohorte externa con etiquetas y fuentes verificadas |
| `data_manifests/domain_overlap_audit.csv` | CSV | 1,200 registros | Auditoría de fuga de datos (0 solapamientos) |
| `data_manifests/acquisition_attempts.csv` | CSV | 600 registros | Trazabilidad de disponibilidad de modalidades en vivo |
| `data_manifests/cascade_paired_predictions.csv` | CSV | 691 registros | Predicciones pareadas de todas las etapas $M_0, M_1, M_2$ |
| `tables/master_classifier_performance.csv` | CSV | 7 modelos/etapas | Métricas canónicas ($F_1$, Precisión, Recall, FPR, ROC-AUC) |
| `tables/master_inferential_statistics.csv` | CSV | 7 hipótesis | Pruebas estadísticas formales con corrección FDR |

---

## 6. Contacto y Soporte para Revisores

Para consultas sobre la auditoría o la reproducción de los experimentos:
- **Repositorio:** [https://github.com/tommy260803/Seguridad_Informacion](https://github.com/tommy260803/Seguridad_Informacion)
- **Equipo de Auditoría y Reproducibilidad:** PhishPe Research Group / MLOps & Scientific Audit Team
