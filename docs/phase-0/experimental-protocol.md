# Protocolo experimental

## Registro previo y orden de trabajo

Antes de ejecutar el test final se congela un manifiesto con pregunta, hipotesis,
metricas primarias, exclusiones, splits, semillas, modelos candidatos, espacio de
hiperparametros, calibracion, politica, pruebas estadisticas y hashes. Los cambios
posteriores se marcan como exploratorios.

Orden obligatorio: adquirir y versionar datos; auditar calidad; crear splits;
entrenar en train; elegir hiperparametros, calibradores, umbrales y presupuestos en
validation; sellar configuracion; ejecutar test una vez; generar resultados.

## Fuentes y snapshot

### Phishing

Fuente inicial: feed descargable de entradas verificadas y online de PhishTank. Se
conservan ID de fuente, URL, submission/verification time, target, ETag, instante de
descarga, hash y terminos aplicables. El feed se versiona antes de cualquier filtro.
PhishTank publica feeds actualizados por hora y campos de verificacion, pero
`online` describe el instante del feed, no garantiza disponibilidad al capturar.

### Legitimos

Fuente inicial: una lista Tranco identificada por su ID permanente, fecha y hash.
El muestreo se estratifica por bandas de popularidad para no confundir legitimidad
con pertenecer unicamente a los sitios mas populares. Tranco aporta reproducibilidad
de la lista, no una garantia de que cada pagina sea benigna; se documentan revision,
fallos de captura y posibles etiquetas ruidosas.

### Subconjunto financiero

Se deriva mediante el campo `target` y una taxonomia versionada, seguido de revision
documentada. Se conserva tambien un conjunto general para evitar que la arquitectura
aprenda solo vocabulario bancario. La taxonomia se crea sin consultar test.

Referencias de las fuentes:

- [PhishTank Developer Information](https://phishtank.net/developer_info.php)
- [Tranco, ranking reproducible para investigacion](https://tranco-list.eu/)

## Inclusion, exclusion y deduplicacion

Se incluyen URLs HTTP(S) con etiqueta y timestamp de fuente. Se excluyen entradas
malformadas, esquemas no permitidos, duplicados exactos, conflictos de etiqueta no
resueltos y muestras cuya licencia/terminos impidan el uso previsto. La no
disponibilidad durante captura no elimina automaticamente la muestra URL-only; se
registra y solo limita experimentos que requieren artefactos.

La deduplicacion ocurre en niveles: URL canonicalizada, host/dominio registrable,
cadena de redireccion final y hashes perceptuales/de contenido. No se deduplican
train y test por separado: primero se crean grupos, luego se asigna el grupo completo
a una particion.

### Coherencia temporal de las evidencias

DNS, TLS, redirecciones, HTML y screenshots cambian con el tiempo. Una muestra
historica no se enriquece consultando el sitio durante una fecha posterior y luego
se presenta como si esa evidencia existiera al momento de la etiqueta. Los
experimentos multimodales usan artefactos capturados en una ventana documentada
respecto de `label_observed_at`; se registra el desfase y se analiza su distribucion.
Si solo existe evidencia actual, el resultado se declara como estudio de snapshot
actual y no como evaluacion retrospectiva o temporal.

Ningun servicio de reputacion consultado despues de la fecha de corte se usa como
feature para el test temporal. Las referencias de marcas, Public Suffix List y otros
recursos externos tambien quedan versionadas por corrida.

## Particiones obligatorias

1. **Convencional:** split estratificado por etiqueta despues de agrupar duplicados
   exactos o casi identicos. Un mismo dominio puede aparecer en mas de una particion;
   esta es la condicion baseline y su solapamiento se informa explicitamente.
2. **Host-unseen:** ningun host ni dominio registrable de test aparece en train o
   validation. Si existen campanas, el grupo mayor (campana/dominio) gobierna.
3. **Temporal:** train precede a validation y validation precede a test segun el
   timestamp de etiqueta/fuente. Las URLs duplicadas no cruzan ventanas. Se informa
   el solapamiento de dominios y se añade un resultado temporal host-unseen filtrado
   para separar generalizacion temporal de memorizacion de host.

La separacion minima entre el primer y ultimo snapshot se preespecifica en la
configuracion antes de recolectar la serie. La configuracion inicial usa 30 dias;
si no se alcanza, el split temporal se marca como no disponible.

El informe de cada split incluye muestras, clases, dominios, hosts, campanas,
periodo, disponibilidad, fuentes, exclusiones y auditoria de intersecciones.

## Preprocesamiento y entrenamiento

Los transformadores se ajustan solo con train. La seleccion de features, imputacion,
balanceo, calibracion y umbrales viven dentro del pipeline de entrenamiento. Se
comparan inicialmente un modelo lineal regularizado y un modelo de arboles adecuado
para datos tabulares; modelos mas complejos requieren mejora demostrada.

Cada etapa posee un modelo que usa el prefijo de modalidades disponible. Esto evita
imputar como si se hubieran observado modalidades omitidas. M0-M3 y M4/M5 reutilizan
los mismos modelos por etapa para aislar el efecto de la politica.

## Calibracion, abstencion y presupuesto

La calibracion usa particiones internas de train o validation sin tocar test. Se
comparan sigmoid/Platt e isotonic cuando el volumen lo soporte, seleccionando con
Brier score y curvas de confiabilidad. ECE se reporta con el esquema de bins fijado
en el manifiesto y acompañado de Brier porque ECE depende del binning.

Los umbrales de clase, abstencion y adquisicion se eligen en validation. Se generan
curvas coverage-risk y rendimiento-coste. Se preseleccionan puntos operativos antes
de test, incluido uno que limite FPR y otro orientado a Recall, sin declarar despues
el punto que resulte mas favorable como unico resultado.

## Baselines y ablaciones

- M0: URL-only.
- M1: URL + infraestructura.
- M2: URL + infraestructura + HTML/DOM.
- M3: todas las modalidades siempre.
- M4: adquisicion adaptativa, decision binaria forzada al final.
- M5: M4 con abstencion calibrada.

Se añade un baseline trivial de prevalencia para controles de pipeline. Las listas
de reputacion, si se estudian, se reportan separadas porque su cobertura temporal
puede filtrar conocimiento posterior y no prueba generalizacion por features.

## Metricas

La clase positiva es phishing. Se reportan matriz de confusion, Precision, Recall,
F1, Specificity, FPR, ROC-AUC y PR-AUC con intervalos. PR-AUC y FPR reciben especial
atencion ante desbalance. No se optimiza ni concluye solo con Accuracy.

Operacion: latencia end-to-end y por modalidad (p50/p95/p99), CPU, memoria pico,
bytes, tiempo sandbox, timeouts, errores, llamadas/tokens/coste LLM y coste estimado.
Adaptacion: distribucion de punto de parada, porcentaje por modalidad, promedio de
modalidades, ahorro y rutas. Abstencion: coverage, selective risk, error y calibracion.

## Analisis estadistico

- Intervalos de confianza del 95% mediante bootstrap pareado y agrupado por dominio
  o campana, con semillas y numero de replicas registrados.
- McNemar pareado para diferencias de error binario en las mismas muestras cuando
  sus supuestos apliquen.
- Diferencias de latencia/coste con bootstrap pareado; mediana y percentiles ademas
  de la media por distribuciones asimetricas.
- Correccion Holm para familias de comparaciones confirmatorias.
- Magnitud del efecto e intervalo siempre; el valor p no decide por si solo.
- Resultados por fuente, periodo y sector financiero/general para detectar sesgo.

Muestras sin modalidad por timeout o bloqueo permanecen en el analisis intention-to-
evaluate. Se reporta aparte el subconjunto con artefactos completos, marcado como
analisis condicionado y potencialmente sesgado.

## Experimento de generalizacion

Se ejecuta cada configuracion congelada en convencional agrupado, host-unseen y
temporal. Para cada metrica se calcula degradacion absoluta y relativa respecto al
convencional. H3 compara si M4/M5 pierden menos que M0; no basta con que conserven
una cifra alta aislada.

## Experimento adversarial

Sobre copias controladas de phishing del test se generan perturbaciones con semilla
y transformacion versionada:

- URL: caracteres, homoglyph/punycode, leetspeak, subdominio, path y query;
- infraestructura: cadenas de redireccion sinteticas en el laboratorio;
- contenido: cambios semantica-preservantes en DOM, clases, texto y orden;
- visual: variaciones leves de layout, escala y estilo que conservan la tarea;
- combinadas, con un presupuesto de perturbacion declarado.

Se valida manual o automaticamente que la etiqueta siga siendo phishing y que la
pagina sea funcional como fixture inerte. Se mide attack success rate, caida de
Recall/F1, cambio de probabilidad, ruta, coste y explicacion. No se publican ni
despliegan paginas fraudulentas.

## Experimento de explicabilidad

A compara una explicacion libre de LLM aislada del clasificador; B usa evidencia
estructurada y exige referencias. Un protocolo de anotacion ciego evalua:

- fidelidad: afirmaciones respaldadas / afirmaciones verificables;
- trazabilidad: afirmaciones con `evidence_id` valido;
- completitud: evidencias decisivas cubiertas;
- consistencia: variacion entre repeticiones equivalentes;
- estabilidad: cambio ante perturbacion pequena que no cambia la decision.

La evaluacion automatica verifica referencias; la evaluacion humana, si se aprueba
mas adelante, usa al menos dos anotadores, guia versionada y acuerdo interanotador.
No se inicia un estudio con usuarios sin protocolo etico y detector estable.

## Reproducibilidad y exportacion

Cada experimento produce:

- manifiesto YAML/JSON sellado y hashes de entradas;
- entorno/contenedores fijados y lockfiles;
- splits como listas de IDs, nunca regenerados implicitamente;
- modelos, calibradores, politicas y feature registry versionados;
- predicciones por muestra y eventos de ruta en formato tabular;
- tablas CSV/JSON y figuras generadas por scripts;
- informe de fallos, exclusiones y desviaciones.

Los resultados incluyen tablas, confusion matrix, ROC, Precision-Recall,
coverage-risk, calibracion, latencia/coste, rutas, generalizacion y robustez.

## Criterio de avance por fase

Una fase es reproducible si otra ejecucion desde un entorno limpio puede verificar
hashes, reconstruir su dataset derivado, ejecutar pruebas y regenerar el informe a
partir de un comando documentado. Para avanzar se revisan tambien leakage, errores,
seguridad y desviaciones. No se requiere un resultado positivo; si una modalidad no
aporta valor frente a su coste, se conserva el hallazgo y se propone eliminarla.

## Referencias metodologicas y tecnicas

- [scikit-learn: Probability calibration](https://scikit-learn.org/stable/modules/calibration.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Tranco methodology and permanent list IDs](https://tranco-list.eu/)
- [PhishTank feed fields and update policy](https://phishtank.net/developer_info.php)
