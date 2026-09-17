# Informe de la primera ejecucion real

## Identificacion

- Snapshot: `20260916T165912.999049Z`
- Observado: `2026-09-16T16:59:12.999049Z`
- Dataset: `0.1.0`
- Semilla: `20260916`
- Python: `3.13.7`
- Tranco ID consultado en la fecha de adquisicion: `N2PYW`

## Entradas

| Fuente | Bytes | SHA-256 |
|---|---:|---|
| PhishTank online-valid | 2,264,118 | `53b31d60ef65167f6c1d2af0ca4c5dd5765100fffeeed83ec2367bf3f138f893` |
| Tranco | 9,713,825 | `553242b62ae505a997506c2b31386acbef484f5b4f777b41b6b1dacb8c338774` |
| Public Suffix List | 334,129 | `bb3d3bb844f1d172de41f0c5089e7b2b7243b02698e4a64120ffcf49ec84c0ee` |

El ID de Tranco se anoto tras consultar su endpoint oficial el mismo dia. Esta
primera version del manifiesto no lo incorporo automaticamente; las adquisiciones
posteriores si lo registran mediante `version_url`. El hash del archivo mantiene la
identidad exacta de esta entrada.

## Resultado procesado

| Medida | Valor |
|---|---:|
| Muestras totales | 175,796 |
| Legitimas | 99,994 |
| Phishing | 75,802 |
| Hosts unicos | 140,931 |
| Dominios registrables unicos | 129,812 |
| Conflictos de etiqueta excluidos | 13 |
| Duplicados de igual etiqueta eliminados | 428 |
| URLs invalidas excluidas | 3 |

El split convencional contiene 123,058 muestras de train, 26,369 de validation y
26,369 de test. Permite solapamiento de dominio de forma deliberada como baseline:
hay 1,658 dominios compartidos entre train y test.

El split host-unseen conserva los mismos tamaños y distribuciones de clase, con
cero dominios compartidos entre cualquiera de sus particiones. Las auditorias
tambien confirman cero `sample_id` compartidos.

El split temporal esta **no disponible** porque solo existe un snapshot. Se requieren
al menos tres fechas y una ventana minima de 30 dias; no se generaron asignaciones
temporales artificiales.

## Integridad

El manifiesto procesado contiene siete artefactos y todos se verificaron de nuevo
contra su SHA-256. Los datos crudos y procesados permanecen bajo `data/`, fuera de
Git por contener URLs potencialmente activas.

Se reconstruyo el snapshot con el codigo actualizado en un directorio independiente.
Los siete hashes de salida coincidieron exactamente con la primera construccion.

## Limitaciones antes de cerrar la fase

- reunir snapshots durante la ventana temporal preespecificada;
- revisar institucionalmente los terminos vigentes y la retencion de URLs;
- auditar una muestra de etiquetas y los 13 conflictos;
- decidir si 100,000 dominios Tranco ofrecen el balance y cobertura adecuados;
- documentar el ID permanente automaticamente en el siguiente snapshot.
