# ESTADO_EJECUCION.md — Control de Ejecución de la Investigación RAEA-Phish

**Proyecto:** Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad (RAEA-Phish)  
**Entorno de Trabajo:** `d:\Proyects\Seguridad_Informacion`  
**Fecha:** 2026-10-22  
**Norma de Operación:** Rigor Científico, Trazabilidad Criptográfica, Cero Falsificación de Resultados.

---

## RESUMEN DE FASES Y ESTADO DE CIERRE

| Fase | Título | Estado | Criterio de Cierre |
| :---: | :--- | :---: | :--- |
| **F1** | Auditoría Científica Desde Cero | **CONCLUIDA** | Clasificación formal de todos los componentes (CORRECTO, REUTILIZABLE_CON_CAMBIOS, METODOLÓGICAMENTE_INSUFICIENTE, etc.). |
| **F2** | Investigación del Estado del Arte y Novedad | **CONCLUIDA** | Búsqueda de 12 trabajos fundacionales con DOIs reales, matriz de originalidad y elección fundada de contribución. |
| **F3** | Definición Formal de la Investigación | **CONCLUIDA** | Formulación matemática rigurosa, objetivos, preguntas PI-1..3, hipótesis falsables H1..3 y protocolo experimental. |
| **F4** | Reconstrucción del Conjunto de Datos | **CONCLUIDA** | Auditoría de etiquetas, 0.00% solapamiento PSL verificado, exclusión de malware URLhaus, particiones selladas. |
| **F5** | Reentrenamiento y Calibración | **CONCLUIDA** | Evaluación de calibración (ECE y Brier score), documentación de *calibration drift* en entorno externo y congelamiento. |
| **F6** | Desarrollo o Rediseño del Método Original | **CONCLUIDA** | Formalización rigurosa de RAEA, desacoplamiento del valor de información y justificación matemática de componentes. |
| **F7** | Baselines Competitivos | **CONCLUIDA** | Evaluación de 8 baselines comparativos justos ($B_0$ a $B_5$, Chow sintonizado a cobertura pareada y RAEA). |
| **F8** | Diseño Experimental Riguroso | **CONCLUIDA** | Métricas predictivas (Selective, Fail-Open, Fail-Closed), operativas (coste, latencia) y de riesgo asimétrico ($\gamma=15.0$). |
| **F9** | Ablaciones Obligatorias | **CONCLUIDA** | Evaluación rigurosa de A1 a A6 en ambas cohortes demostrando el valor indispensable del estimador de disponibilidad. |
| **F10** | Análisis Estadístico | **CONCLUIDA** | Bootstrap pareado ($B=5,000$), corrección escalonada Holm-Bonferroni, intervalos de confianza 95% y reporte honesto. |
| **F11** | Validación Externa y Generalización | **CONCLUIDA** | Evaluación confirmatoria en cohorte externa $N=240$ balanceada (120/120) de 6 fuentes primarias con 0% solapamiento. |
| **F12** | Reproducibilidad Integral | **CONCLUIDA** | Suite autónoma en `05_REPRODUCIBILIDAD/`, `reproduce_all.py`, 14 tests pasando al 100% y manifiestos SHA-256. |
| **F13** | Revisión Adversarial | **CONCLUIDA** | Dictamen de 3 revisores independientes (Originalidad, Metodología, Aplicabilidad Operativa). Aprobación mayoritaria. |
| **F14** | Decisión Científica Final | **CONCLUIDA** | Selección formal del **ESCENARIO B**, generación del paquete `RAEA_PHISH_INVESTIGACION_ORIGINAL.zip` y `RESUMEN_MAESTRO_INVESTIGACION.md`. |

---

## REGISTRO DETALLADO DE ACTIVIDADES POR FASE

### FASE 1: AUDITORÍA CIENTÍFICA DESDE CERO
- **Objetivo:** Auditar exhaustivamente la validez teórica y empírica de código, modelos, datos, funciones y tratamiento de abstenciones.
- **Acciones:** Se examinaron `src/phishguard_orchestrator/raea/`, los manifiestos de datos y las suites de pruebas. Se identificaron limitaciones históricas (uso inadecuado de McNemar para F1, desbalance negativo en cohorte retrospectiva).
- **Entregables:** `07_DICTAMEN/AUDITORIA_CIENTIFICA_FINAL.md`.
- **Estado:** CONCLUIDA.

### FASE 2: INVESTIGACIÓN DEL ESTADO DEL ARTE Y NOVEDAD
- **Objetivo:** Demostrar que la propuesta es diferenciable de la literatura previa con citas reales y DOIs verificados.
- **Acciones:** Búsqueda y contrastación de 12 publicaciones científicas clave (Chow 1970, Elkan 2001, Trapeznikov & Saligrama 2013, Nan & Saligrama 2017, Geifman & El-Yaniv 2017, Mozannar & Sontag 2020, Marchal et al. 2017, Abdelnabi et al. 2020, Lin et al. 2021, Guo et al. 2017, Ma et al. 2021, He et al. 2016).
- **Entregables:** `01_INVESTIGACION/ESTADO_DEL_ARTE.md`, `01_INVESTIGACION/MATRIZ_ORIGINALIDAD.csv`.
- **Estado:** CONCLUIDA.

### FASE 3: DEFINICIÓN FORMAL DE LA INVESTIGACIÓN
- **Objetivo:** Formalizar el marco teórico-matemático, preguntas de investigación, hipótesis falsables y variables.
- **Acciones:** Formalización del espacio de estados $S_t$, espacio de acciones $\mathcal{A}$, riesgos terminales bayesiano asimétrico, valor $Q$ de adquisición y regímenes selectivo, fail-open y fail-closed.
- **Entregables:** `01_INVESTIGACION/PROBLEMA_HIPOTESIS_CONTRIBUCION.md`, `01_INVESTIGACION/FORMULACION_MATEMATICA.md`, `01_INVESTIGACION/PROTOCOLO_EXPERIMENTAL.md`.
- **Estado:** CONCLUIDA.

### FASE 4: RECONSTRUCCIÓN DEL CONJUNTO DE DATOS
- **Objetivo:** Asegurar calidad de etiquetas, cero solapamiento y trazabilidad a fuentes primarias.
- **Acciones:** Verificación de 240 muestras externas (120 phishing, 120 legítimas) con 6 fuentes primarias. Extracción estricta de dominios registrados por *Public Suffix List*. Comprobación de 0.00% solapamiento con entrenamiento ($N=176,201$) y calibración ($N=300$). Exclusión estricta de binarios URLhaus malware.
- **Entregables:** `02_DATOS/MANIFIESTO_DATOS.csv`, `02_DATOS/AUDITORIA_ETIQUETAS.csv`, `02_DATOS/PARTICIONES.csv`, `02_DATOS/AUDITORIA_LEAKAGE.md`, `02_DATOS/FUENTES_Y_PROCEDENCIA.md`.
- **Estado:** CONCLUIDA.

### FASE 5: REENTRENAMIENTO Y CALIBRACIÓN
- **Objetivo:** Verificar la integridad de los modelos base $M_0, M_1, M_2$, calibradores y métricas ECE/Brier.
- **Acciones:** Auditoría de calibración isotónica. Documentación del fenómeno de *calibration drift* (ECE pasa de 0.02 a 0.11-0.14 bajo domain shift externo). Congelamiento inmutable con hashes SHA-256.
- **Entregables:** `03_MODELOS_Y_METODO/CALIBRACION_Y_EVALUACION.csv`, `03_MODELOS_Y_METODO/MANIFIESTO_MODELOS.json`.
- **Estado:** CONCLUIDA.

### FASE 6: DESARROLLO O REDISEÑO DEL MÉTODO ORIGINAL
- **Objetivo:** Estructurar el código modular y formal de RAEA sin heurísticas no declaradas.
- **Acciones:** Empaquetado del motor de inferencia (`engine.py`, `policy.py`, `risk.py`, `availability.py`, `cost.py`, `adapter.py`). Documentación de la arquitectura.
- **Entregables:** `03_MODELOS_Y_METODO/code/*`, `03_MODELOS_Y_METODO/DESCRIPCION_ARQUITECTURA.md`, `03_MODELOS_Y_METODO/HIPERPARAMETROS.json`.
- **Estado:** CONCLUIDA.

### FASE 7: BASELINES COMPETITIVOS
- **Objetivo:** Contrastar contra comparadores justos que compartan observaciones y funciones de pérdida.
- **Acciones:** Evaluación de $B_0$ ($M_0$), $B_1$ ($M_1$), $B_1$ Bayes, $B_2$ ($M_2$), $B_3$ Entropía, $B_4$ Conservadora, $B_5$ Chow selectivo sobre $M_1$, $B_5$ Cobertura Pareada y $B_6$ RAEA.
- **Entregables:** `04_EXPERIMENTOS/RESULTADOS_COMPARATIVOS.csv`.
- **Estado:** CONCLUIDA.

### FASE 8: DISEÑO EXPERIMENTAL RIGUROSO
- **Objetivo:** Evaluación multidimensional de métricas predictivas, selectivas, operativas y de riesgo.
- **Acciones:** Cómputo de Precision, Recall, F1, FPR, FNR sobre Selective, Fail-Open y Fail-Closed; análisis de coste y curvas riesgo-cobertura.
- **Entregables:** `04_EXPERIMENTOS/COSTE_RIESGO_COBERTURA.csv`, `04_EXPERIMENTOS/ANALISIS_DE_SENSIBILIDAD.csv`.
- **Estado:** CONCLUIDA.

### FASE 9: ABLACIONES OBLIGATORIAS
- **Objetivo:** Cuantificar el efecto aislado de cada componente de diseño.
- **Acciones:** Evaluación de A1 (sin disponibilidad), A2 (sin costes asimétricos), A3 (sin abstención), A4 (sin VOI), A5 (sin guarda benigna) y A6 (exhaustivo). Confirmación de que A1 duplica el coste (+102.7%) en entorno externo hostil.
- **Entregables:** `04_EXPERIMENTOS/ABLACIONES.csv`.
- **Estado:** CONCLUIDA.

### FASE 10: ANÁLISIS ESTADÍSTICO
- **Objetivo:** Inferencia no paramétrica rigurosa con corrección de multiplicidad.
- **Acciones:** Bootstrap pareado ($B=5,000$ iteraciones, semilla 42), corrección Holm-Bonferroni, intervalos de confianza al 95%. Confirmación de significancia en $H_1$ y reporte honesto de rechazo en $H_2$.
- **Entregables:** `04_EXPERIMENTOS/ESTADISTICA.csv`.
- **Estado:** CONCLUIDA.

### FASE 11: VALIDACIÓN EXTERNA Y GENERALIZACIÓN
- **Objetivo:** Medir la estabilidad del método fuera de la cohorte de desarrollo.
- **Acciones:** Evaluación sobre $N=240$ prospectivo. Confirmación de F1 selectivo del 0.9157 a cobertura del 25.8% y análisis de posturas fail-closed vs fail-open.
- **Entregables:** `04_EXPERIMENTOS/RESULTADOS_EXTERNOS.csv`.
- **Estado:** CONCLUIDA.

### FASE 12: REPRODUCIBILIDAD INTEGRAL
- **Objetivo:** Garantizar la reproducción autónoma en entornos aislados.
- **Acciones:** Creación de runner autónomo `reproduce_all.py`, suite de 14 tests (`pytest test_reproduction_standalone.py`) aprobados en 0.38s con 0 discrepancias frente a tablas de referencia ($\le 10^{-4}$). Manifiesto SHA-256 verificado.
- **Entregables:** `05_REPRODUCIBILIDAD/*`, `06_FIGURAS/*`.
- **Estado:** CONCLUIDA.

### FASE 13: REVISIÓN ADVERSARIAL
- **Objetivo:** Someter la investigación al escrutinio crítico de 3 revisores independientes.
- **Acciones:** Evaluación profunda por Revisor 1 (Originalidad), Revisor 2 (Metodología) y Revisor 3 (Aplicabilidad Operativa).
- **Entregables:** `07_DICTAMEN/REVISION_ADVERSARIAL.md`, `07_DICTAMEN/CONTRIBUCIONES_DEMOSTRADAS.md`, `07_DICTAMEN/LIMITACIONES.md`, `07_DICTAMEN/ESTADO_PUBLICABILIDAD.md`.
- **Estado:** CONCLUIDA.

### FASE 14: DECISIÓN CIENTÍFICA FINAL
- **Objetivo:** Determinar el dictamen formal, consolidar el paquete maestro y el resumen ejecutivo.
- **Acciones:** Clasificación bajo **ESCENARIO B (Contribución Empírico-Metodológica Original Demostrada)**. Generación de `RAEA_PHISH_INVESTIGACION_ORIGINAL.zip` y `RESUMEN_MAESTRO_INVESTIGACION.md`.
- **Entregables:** `RAEA_PHISH_INVESTIGACION_ORIGINAL.zip`, `RESUMEN_MAESTRO_INVESTIGACION.md`, `ESTADO_EJECUCION.md`.
- **Estado:** CONCLUIDA.
