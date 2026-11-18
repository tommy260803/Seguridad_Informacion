# Protocolo de Reproducción Autónoma e Independiente (RAEA-Phish)

Este paquete permite reproducir íntegramente de manera autónoma e independiente los resultados científicos, matrices de confusión, análisis de coste, contrastes de hipótesis y figuras del método **RAEA-Phish** (*Risk- and Availability-Aware Adaptive Evidence Acquisition*).

## Contenido del Paquete

- `reproduce_all.py`: Script maestro ejecutable de reproducción dual. Valida la integridad de datos, recalcula métricas selectivas, fail-open y fail-closed estrictas, ablaciones A1-A6, contrastes Bootstrap pareados y genera las figuras científicas.
- `test_reproduction_standalone.py`: Suite de 14 pruebas formales automatizadas (`pytest`) que verifican matemáticamente las definiciones de abstención, conservación de muestras, cero fuga de datos (zero-leakage), consistencia de esquemas y tolerancias de métricas ($\le 10^{-4}$).
- `data/`:
  - `COHORTE_Y_ETIQUETAS.csv`: Metadatos y etiquetas congeladas de la cohorte retrospectiva ($N=600$, población primaria $N=118$).
  - `PREDICCIONES_INDIVIDUALES.csv`: Trajectorias, estados selectivos y predicciones por URL para todas las políticas en la cohorte retrospectiva.
  - `COHORTE_EXTERNA.csv`: Muestras de la cohorte externa independiente ($N=240$: 120 phishing, 120 legítimas) con dominios registrados PSL y telemetría de red.
  - `PREDICCIONES_EXTERNAS.csv`: Predicciones y secuencias de decisión de las 13 políticas en la cohorte externa.
  - `AUDITORIA_COHORTE_EXTERNA.csv`: Auditoría individual de procedencia, categorización en 5 niveles de calidad y verificación formal de solapamiento nulo (0.00% fuga de datos).
  - `run_metadata.json`: Metadatos del entorno y hashes de congelamiento.
- `environment_specs.json`: Especificación técnica del entorno de ejecución Python y librerías utilizadas.

## Instrucciones de Ejecución

### 1. Ejecución del Script Maestro de Reproducción

```bash
python reproduce_all.py
```

El script ejecutará las 7 fases de reproducción:
1. Validación de integridad criptográfica SHA-256 de los archivos de datos.
2. Auditoría de independencia experimental (cero solapamiento con train/calib/retro).
3. Recálculo de métricas en la Cohorte Retrospectiva ($N=118$).
4. Recálculo de métricas en la Cohorte Externa Independiente ($N=240$).
5. Evaluación de variantes de ablación (A1 a A6) en ambas cohortes.
6. Contrastes inferenciales Bootstrap pareados ($B=5,000$) con corrección Holm-Bonferroni.
7. Generación de figuras comparativas duales en `output/FIGURAS/`.

### 2. Ejecución de la Suite de Pruebas Automatizadas

```bash
pytest test_reproduction_standalone.py -v
```

Verifica 14 asertos obligatorios con tolerancia estricta ($< 10^{-4}$).

## Definición Rigurosa de Políticas de Abstención

1. **Selectiva (Selective):**
   Las observaciones donde la política emite `ABSTAIN` se excluyen de la matriz binaria de decisión. Permite evaluar la precisión y F1 condicional sobre las muestras donde el modelo posee certidumbre epistémica.
2. **Fail-Open (Apertura Segura, fill=0):**
   Las abstenciones se tratan como benignas/legítimas (`0`). Las abstenciones de sitios phishing se convierten en Falsos Negativos ($FN$), mientras que las abstenciones de sitios legítimos se convierten en Verdaderos Negativos ($TN$).
3. **Fail-Closed (Cierre Seguro, fill=1):**
   Las abstenciones se tratan como sospechosas/phishing (`1`). Las abstenciones de sitios phishing se convierten en Verdaderos Positivos ($TP$), mientras que las abstenciones de sitios legítimos se convierten en Falsos Positivos ($FP$).
