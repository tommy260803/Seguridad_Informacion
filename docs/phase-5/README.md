# Fase 5 - Evidencia visual

Esta fase incorpora un extractor visual offline para screenshots generados por
el sandbox. El extractor usa únicamente señales geométricas y estadísticas de
imagen acotadas: dimensiones, relación de aspecto, luminancia, densidad de
bordes y saturación.

## Contrato

`phishguard_visual.analyzer.analyze_screenshot` recibe una ruta local y aplica
límites de bytes y píxeles. Devuelve `success`, `blocked` o `error`, junto con
evidencia estructurada. No ejecuta navegador, JavaScript ni red, y no guarda
los píxeles en el resultado.

El adaptador `phishguard_ml.visual` expone nueve features versionadas como
`visual-features-1.0.0`. La ausencia o el bloqueo de una captura se conserva
como observación no disponible, nunca como una imagen normal.

## Gate

- capturas reales únicamente desde un worker sandbox autorizado;
- límites de tamaño, píxeles y memoria verificados con fixtures;
- comparación visual avanzada pendiente de definir y evaluar contra un
  conjunto de referencia, sin usarla aún como autoridad de clasificación;
- M3/M4 no se entrenan hasta congelar este contrato y disponer de artefactos
  representativos.
