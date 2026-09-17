# Fase 12 - Evaluación final y exportación

`phisheval` agrega los artefactos de M0, M1, M2 y M3 únicamente cuando comparten
los hashes de `samples.csv` y del split. Exporta `report.json` y `report.csv`
con métricas de test ya congeladas y deltas respecto a M0. El protocolo marca
explícitamente que test no se usó para seleccionar features, modelos ni umbrales.

La ejecución sobre datos reales queda pendiente de disponer de artefactos de
infraestructura, contenido y visual capturados bajo autorización. El agregador
no rellena ausencias ni fabrica resultados.
