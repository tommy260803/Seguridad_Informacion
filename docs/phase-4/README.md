# Fase 4 - Contenido HTML/DOM

Esta fase comienza por un extractor bounded sobre artefactos HTML ya capturados.
No ejecuta JavaScript, no realiza solicitudes de red y no interpreta el contenido
de la pagina como instrucciones.

## Features iniciales

El paquete `phishguard_content` registra tamaño y truncamiento, tags, titulo, texto,
formularios, inputs de password/email/pago, scripts, iframes, enlaces y recursos
externos, acciones externas de formularios y terminos de login/pago.

Todos los valores salen de un registro estructurado y cada feature genera evidencia
con fuente `html-dom`. El parser usa limites configurables de bytes, tags, texto y
atributos; contenido no HTML produce `blocked` y un tipo de error explícito.

El adaptador `phishguard_ml.content` transforma los resultados en 21 features
versionadas (`content-features-1.0.0`) y conserva por separado `success`, `blocked`,
`error` y ausencia de captura. Esto prepara M2 sin imputar fallos como contenido
normal.

## Gate

- captura HTML real solo desde el worker sandbox ya verificado;
- descargas, formularios y subrecursos controlados por politica de red;
- limites de bytes, tiempo, DOM y memoria probados con fixtures adversariales;
- features M2 versionadas y comparables contra M1;
- ninguna selección de modelo o umbral consulta `test`.

La captura representativa de Fase 4 permanece bloqueada hasta cerrar la evaluación
M1 y obtener autorización para adquisiciones externas.

El entrenador `phishm2` combina las features URL, infraestructura y contenido con
el mismo protocolo de calibracion y umbral; requiere `results.jsonl` de ambas
modalidades y no navega por su cuenta.
