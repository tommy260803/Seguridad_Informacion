# Fase 1 - Pipeline de datos

## Problema cientifico

Una comparacion multimodal no es valida si las etiquetas, snapshots o particiones
no pueden reconstruirse, o si variantes de una misma URL/dominio contaminan train
y test. Esta fase convierte feeds externos en un dataset versionado sin navegar a
las URLs listadas.

## Componentes

- adquisicion HTTP de feeds conocidos con limites, metadata y SHA-256;
- lectores de PhishTank, Tranco y Public Suffix List;
- validacion y canonicalizacion de URL;
- deduplicacion determinista y reporte de exclusiones;
- splits convencional, host-unseen y temporal;
- auditoria de leakage, estadisticas y manifiesto de reproduccion;
- CLI, configuracion de ejemplo y pruebas con fixtures inertes.

## Entradas

Un directorio snapshot contiene:

- feed CSV/JSON de PhishTank, posiblemente gzip/bzip2/zip;
- CSV de Tranco, posiblemente zip;
- snapshot de Public Suffix List;
- `acquisition-manifest.json` generado durante la descarga.

El pipeline nunca visita las URLs contenidas en esos feeds. La captura de HTML y
screenshot pertenece a fases posteriores y queda bloqueada por el modelo de
amenazas.

## Salidas

Cada version procesada produce:

- `samples.jsonl` y `samples.csv`;
- asignaciones de split en CSV para `conventional`, `host_unseen`, `temporal` y
  `temporal_host_unseen`;
- `statistics.json` con distribuciones, exclusiones y auditoria;
- `manifest.json` con configuracion, hashes, entorno y archivos de salida.

Los datos generados viven bajo `data/` y no se incluyen en Git. Fixtures sinteticos
pequenos viven en `tests/fixtures/`.

## Evaluacion de la fase

La fase se verifica con pruebas de canonicalizacion, reglas PSL, parsers comprimidos,
determinismo, separacion de dominios y orden temporal. Una prueba end-to-end debe
regenerar exactamente los mismos hashes con los mismos datos/configuracion.

La configuracion fija tambien una separacion temporal minima. Tres descargas
consecutivas no constituyen tres periodos: el split queda indisponible hasta cubrir
la ventana preespecificada. El ID permanente de Tranco se resuelve y registra junto
con el hash del archivo.

## Archivos de implementacion

- `src/phishguard_data/`: paquete del pipeline;
- `configs/data-pipeline.example.json`: configuracion reproducible;
- `tests/`: pruebas unitarias e integracion;
- `data/README.md`: politica de datos y comandos.

## Gate de Fase 1

Para cerrar la fase deben pasar las pruebas, existir un snapshot real con hash y
terminos registrados, revisarse el reporte de calidad y regenerarse un dataset con
el mismo manifiesto. El codigo puede completarse con fixtures antes de descargar
datos reales; la fase no se declara cerrada hasta cumplir esas condiciones.
