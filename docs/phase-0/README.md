# Fase 0 - Diseno cientifico

## Objetivo

Congelar un diseno evaluable antes de programar. Esta fase convierte la idea del
proyecto en hipotesis falsables, contratos de datos, fronteras de seguridad y un
protocolo que evita ajustar decisiones con el conjunto de prueba.

## Entregables

| Documento | Funcion |
|---|---|
| [scientific-design.md](scientific-design.md) | Pregunta, hipotesis, variables, criterios de exito y trazabilidad |
| [architecture.md](architecture.md) | Componentes, flujo adaptativo, despliegue y contratos |
| [data-model.md](data-model.md) | Entidades persistentes, evidencia y versionado |
| [threat-model.md](threat-model.md) | Activos, fronteras de confianza, amenazas y controles |
| [experimental-protocol.md](experimental-protocol.md) | Datos, particiones, baselines, metricas y analisis estadistico |

## Decisiones congeladas

1. La unidad primaria de evaluacion es una URL observada en un instante. Los
   intervalos de confianza se calculan respetando agrupaciones por dominio
   registrable o campana cuando corresponda.
2. La etiqueta objetivo es binaria (`legitimate`, `phishing`). `uncertain` es una
   accion del clasificador selectivo, no una tercera clase de entrenamiento.
3. Cada etapa usa solo la evidencia disponible hasta ese punto. La politica
   decide `stop_legitimate`, `stop_phishing`, `acquire_next` o `abstain`.
4. Los scores se calibran y todos los umbrales de decision, abstencion y coste se
   seleccionan con train/validation. El conjunto de prueba se abre una vez por
   corrida registrada.
5. La primera politica adaptativa sera determinista y auditable. Un LLM puede
   verbalizar evidencias, pero no extraer etiquetas, alterar features ni decidir.
6. Los artefactos web se adquieren solo en el sandbox. El backend de control no
   navega hacia la URL analizada.
7. Las comparaciones adaptativa y fija comparten datos, extractores, modelos por
   etapa y semillas. Solo cambia la politica de adquisicion.

## Gate para iniciar Fase 1

La Fase 0 se considera completa cuando se acepta que:

- cada hipotesis tiene una comparacion, metrica primaria y criterio de apoyo;
- estan definidos la unidad experimental y los tres splits obligatorios;
- el modelo de datos puede reconstruir cualquier decision;
- la arquitectura separa control, ejecucion hostil y persistencia;
- el protocolo de seguridad bloquea SSRF por validacion y por red;
- se registraran versiones de datos, codigo, configuracion, modelos y entorno;
- no quedan umbrales de rendimiento elegidos antes de observar el baseline.

## Gate para cada fase posterior

Una fase solo puede cerrarse si entrega artefactos versionados, pruebas pertinentes,
un informe de metricas y comandos reproducibles. Un resultado negativo no impide
cerrarla: debe registrarse y puede justificar eliminar el componente.

## Fuera de alcance inicial

- entrenamiento de LLM;
- aprendizaje por refuerzo para la politica adaptativa;
- base de datos vectorial;
- microservicios independientes por modalidad;
- evaluacion con personas antes de estabilizar el detector;
- despliegue publico del sandbox;
- interaccion con phishing real fuera del entorno de investigacion.
