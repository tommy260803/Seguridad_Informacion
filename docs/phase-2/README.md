# Fase 2 - Baseline URL-only

## Problema cientifico

El baseline M0 estima cuanto puede detectarse usando solo la cadena URL. Es el
punto de referencia para medir el valor incremental de infraestructura, contenido,
vision y adquisicion adaptativa. Debe ser reproducible, calibrado y suficientemente
interpretable para no atribuir a fases posteriores mejoras debidas a un baseline
debil o mal evaluado.

## Componentes

- extractor versionado de features lexicas y estructurales de URL;
- candidatos controlados: regresion logistica e histogram gradient boosting;
- division determinista de validation en calibracion y seleccion;
- calibracion sigmoid/isotonic elegida sin consultar test;
- seleccion de umbral por F1 en validation-selection;
- metricas de deteccion y calibracion, predicciones y artefacto de modelo;
- registro de versiones, hashes y parametros.

El limite de hilos se fija en configuracion y se aplica al entrenamiento y a la
inferencia para reducir variacion entre maquinas.

### Perfiles de features

`authority_only` es el baseline primario del snapshot PhishTank/Tranco: usa solo
longitud, estructura, caracteres y entropia del host. Evita que el modelo explote
que las muestras Tranco fueron construidas como `https://dominio/` sin paths.

`full_url` incluye path, query, esquema y tokens. Sus resultados actuales son un
diagnostico de sensibilidad y no una estimacion principal hasta incorporar URLs
legitimas completas obtenidas de una fuente reproducible.

## Entradas y salidas

Entrada: `samples.csv`, una asignacion de split y la configuracion del baseline.
El entrenamiento no consulta red ni fuentes externas.

Salida: modelo serializado, feature registry, candidatos de validacion, umbral,
metricas por particion, predicciones y manifiesto con hashes. Las URLs no se copian
a las predicciones; se usa `sample_id`.

La matriz de features puede guardarse en un cache identificado por hash de muestras
y version del extractor. Corridas sobre distintos splits reutilizan ese mismo
artefacto solo si identidad, forma y valores finitos coinciden.

## Protocolo

1. Ajustar extractor/modelo solo en `train`.
2. Dividir `validation` por hash de dominio registrable en `calibration` y
   `selection`, sin permitir que un dominio cruce ambos roles.
3. Ajustar calibrador en `calibration`.
4. Elegir candidato por PR-AUC y Brier en `selection`.
5. Elegir umbral de F1 en `selection` y congelarlo.
6. Evaluar una vez `train`, validation completa y `test`.

Se ejecutan corridas independientes para `conventional` y `host_unseen`. La
comparacion de generalizacion usa la diferencia entre ambas; no se mezclan sus
particiones.

## Evaluacion

Se reportan Accuracy, Precision, Recall, F1, Specificity, FPR, ROC-AUC, PR-AUC,
Brier score y ECE, ademas de matrices de confusion. El umbral 0.5 se conserva como
referencia y el umbral seleccionado se marca explicitamente.

## Gate de Fase 2

- pruebas del extractor, calibracion, metricas y entrenamiento pasan;
- una reconstruccion reproduce hashes y metricas con la misma version;
- existen resultados conventional y host-unseen;
- test no intervino en seleccion ni calibracion;
- limitaciones y degradacion se documentan antes de avanzar.

Los resultados iniciales y la decision de usar `authority_only` como M0 primario se
documentan en [results.md](results.md).
