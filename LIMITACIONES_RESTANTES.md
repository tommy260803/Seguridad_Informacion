# LIMITACIONES RESTANTES — Fase de corrección (2026-10-14)

Este documento lista **todas las limitaciones que siguen vigentes** tras la fase
de corrección, con su impacto cuantificado cuando es medible. Se publica junto a
los entregables para que la auditoría y el artículo puedan citarlas sin ambigüedad.
Cada limitación indica: (i) qué no se pudo hacer, (ii) por qué, (iii) qué
evidencia sí existe y (iv) qué se recomienda.

---

## L1. Los modelos M0–M3 NO se reentrenaron (coste medido de la normalización de `www`)

**Qué.** Los pesos congelados de M0–M3 se entrenaron con el corpus histórico,
que contenía el **atajo de `www`** (subdominio `www` presente solo en la clase
phishing del corpus). La corrección del BUG-07 aplica `_strip_www()` en la
**inferencia**, sin reentrenar.

**Impacto medido.** En la cohorte externa nueva (N = 1,200), la normalización
cuesta 12 detecciones de phishing (F1 0.8829 → 0.8707; McNemar 12 discordantes
todas favor al original, p = 0.000488, Holm p = 0.001465). En la Config C
corregida, 4 URLs phishing con `www` pasan a no detectadas (pares discordantes
A vs C = 4, p = 0.125, **no significativo tras Holm**).

**Contrapartida (el defecto que se resuelve).** El experimento pareado
www/no-www (300 dominios) demuestra que, sin la normalización, **el 100 % de
los dominios legítimos con `www` se clasifican como phishing** (FPR = 1.00) y
que la misma URL cambia de decisión en 170/300 pares. Con la corrección: FPR =
5.33 % (idéntico a la variante sin `www`) y 0/300 discordancias.

**Recomendación.** Reentrenar M0 (y M1/M2 por arrastre) con las características
normalizadas para eliminar el atajo y recuperar el recall en hosts `www`. Es un
trabajo de entrenamiento, no de corrección; queda fuera del alcance de esta fase
para no romper el congelamiento del experimento.

---

## L2. El blend con LLM (BUG-06) no se evaluó end-to-end con un LLM real de pago

**Qué.** La combinación `0.7·p_cascada + 0.3·p_LLM` está corregida en código y
verificada por 3 pruebas de regresión (incluida una con un doble del cliente
LLM). **No** se ejecutó una evaluación con una API de LLM de pago real.

**Por qué.** Requiere una API de pago cuyo uso no está autorizado explícitamente
por la dirección del proyecto (criterio de coste/seguridad; no se usan
credenciales ni tokens sin autorización).

**Impacto.** La corrección es estructural (antes la probabilidad del LLM
**sobrescribía** la de la cascada; ahora se combinan linealmente). El efecto
métrico end-to-end permanece **cuantificado solo por prueba de código**, no por
cohortes. Cualquier cifra de mejora atribuible al LLM sería especulativa y no se
reporta.

**Recomendación.** Evaluar con un modelo local (p. ej. vía `llama.cpp`) o con
una API autorizada, sobre la misma cohorte2 congelada.

---

## L3. Mortalidad de URLs externas y atribución dependiente de la clase

**Qué.** Al sondear URLs reales, una fracción relevante ya no responde (sitios
caídos, bloqueos geográficos, DNS fallido).

**Medido en la cohorte2 (N = 600 sondeados, ejecución vigente).** Completitud
**13,3 %** en phishing vs **69,0 %** en legítimas (completitud total
247/600 = 41,2 %). Es decir, la pérdida **no es aleatoria**: el phishing muere
mucho más que el legítimo.

**Consecuencia metodológica.** Los resultados *complete-case* **no son
representativos** de la población objetivo (inflan el FPR aparente y alteran el
recall). Por eso se reportan **siempre por separado**:

- *Intention-to-evaluate* (denominador = intentos, con estrategia de fallback a
  M0 cuando falta una modalidad): F1 = 0.8246, FPR = 5.00 %, FNR = 26.33 %.
- *Complete-case* (denominador = solo páginas completas, N = 247): M0 F1 = 0.6977.

Las **abstenciones nunca se contabilizan como aciertos**; se publican cobertura
y F1 *solo-decididos* junto a la métrica completa con la abstención contada como
predicción positiva.

---

## L4. El slice de acortadores quedó fuera de la cohorte congelada

**Qué.** La cohorte2 congelada contiene **0 URLs de acortadores** (las cadenas
de redirección se excluyeron en la construcción para que cada fila sea una
etiqueta inequívoca). Por tanto, el comportamiento de los acortadores **no está
evaluado de forma confirmatoria**.

**Evidencia sí disponible (suplementaria, claramente etiquetada).** Se midieron
las cadenas de redirección reales de 250 objetivos (48 con redirecciones) y se
construyó un conjunto suplementario de 16 URLs acortadas (10 phishing /
6 legítimas). Cobertura de la regla de acortadores: 9/16. Exactitud descriptiva:
M0 original 68,8 %, M0 normalizado 68,8 %, Config A 37,5 %, Config C 37,5 %.
**Esto NO es una validación**: N es reducido y la inclusión fue post-hoc.

**Recomendación.** Incluir un estrato de acortadores con etiqueta de destino
final (seguimiento de cadena con congelación del destino) en una futura cohorte.

---

## L5. La modalidad visual (M3) no participa en el sondeo externo

**Qué.** La cascada externa no puede consultar M3: el sondeo externo no genera
capturas de página con Chrome. La Config C corregida marca la modalidad visual
como no disponible (fallback) en lugar de forzarla (BUG-05).

**Impacto.** Las comparaciones de cascada en el sondeo externo cubren
URL + infraestructura + contenido, **no** el aporte visual. Los resultados
internos con capturas auténticas Chrome CDP (N = 83) disponibles son los del
ciclo previo y se mantienen como referencia.

**Recomendación.** Extender el sondeo externo con capturas CDP auténticas para
cerrar la evaluación completa de la cascada.

---

## L6. Potencia estadística limitada para comparaciones pequeñas entre brazos

**Qué.** Con N = 1,200 (600/600) y tasas de discordancia del 0,3–3,7 %, las
comparaciones pareadas solo detectan diferencias moderadas. Ejemplo: Config A
vs Config C tiene 4 pares discordantes (p = 0.125); ninguna comparación de
cascada alcanza significación (p ≥ 0.53).

**Consecuencia.** Las diferencias pequeñas reportadas son **inconclusas**, no
demostradas. Los IC 95 % bootstrap se publican con cada estimación.

**Recomendación.** Para confirmar diferencias del orden de ΔF1 ≈ 0.01 se
requieren cohortes del orden de 10 000–20 000 URLs (estimación de potencia en
`07_ANALISIS_ESTADISTICO.md`).

---

## L7. Umbral de M0 elegido internamente; calibración externa sin recalibración

**Qué.** Los umbrales de todos los modelos (tabla en `REPRODUCIBILIDAD.md` §7)
se seleccionaron en el particionado interno. La evaluación externa mide la
calibración (ECE, Brier) **sin recalibrar**, que es la condición honesta de
validación externa, pero deja abierta la recalibración como mejora futura.

**Dato.** ECE externo de M2 ≈ 0.101 y Brier ≈ 0.135 (sondeo externo vigente),
frente a mejores valores internos: hay **degradación de calibración al dominio
externo**, esperable y reportada.

---

## L8. Congelamiento vs. fecha del artículo

**Qué.** El estado congelado vigente es el *freeze* #5
(`110a954f7b99eced0bcea66a59700e23f8f6cea34f92db4fa9b4c6ec0fae5f62`,
2026-10-14), que incorpora únicamente las correcciones de las auditorías finales
(C‑2, C‑3, B‑07) y los scripts de medición, con modelos, umbrales y snapshots
baseline **byte-idénticos** a los del freeze #3
(`0999ef95…`, 2026-10-14), bajo el que se ejecutó la evaluación de la cohorte2
(prueba en `eval/offline_revalidation.json`, 11/11 PASS). El artículo debe citar
**el freeze #5 como estado del código y el #3 como fecha de evaluación**, no las
fechas de los informes históricos (corregidas en `REPRODUCIBILIDAD.md` §R1).

---

## L9. Coste de cómputo del sondeo externo

**Qué.** El sondeo externo completo (600 URLs con DNS+TLS+HTTP+HTML) tardó
57,4 s de pared con sondeo concurrente; las cadenas de redirección manuales
(250 objetivos) añadieron ~5 min. Los tiempos de cascada reportados son
**tiempos reales de pared medidos por URL**, no sumas de medianas: M4
p50 = 875 ms, p90 = 3 600 ms, p95 = 4 683 ms; conservadora
p50 = 889 ms, p95 = 4 683 ms (infraestructura sola: p50 = 959 ms,
p95 = 3 577 ms).

---

## L10. El Chrome de marca no admite `--load-extension`: la batería E2E corrió en Chrome‑for‑Testing

**Qué.** La batería E2E se intentó primero con el **Google Chrome de marca
instalado** (155.0.8059.40). Ese producto **rechaza** la carga de extensiones
descomprimidas por línea de comandos desde la versión 137; el intento quedó
registrado literalmente:
`--load-extension is not allowed in Google Chrome, ignoring.`
(`artifacts/e2e_chrome/branded_chrome_load_extension.log`).

**Qué se hizo.** La batería se ejecutó en **Chrome‑for‑Testing 156.0.8078.4**
(compilación oficial del mismo motor, build Playwright `chromium-1248`), con
servicio de extensiones, DevTools/CDP y pila de red **reales**, contra un
backend real en `:8080` e Internet público. **No** se usó ASGI ni mocks como
prueba principal.

**Impacto.** El comportamiento medido es el de un Chromium real y actual, pero
**no** se verificó el empaquetado `.crx` ni las directivas de empresa del producto
de consumo. Para despliegue productivo debe empaquetarse la extensión o usar
directivas de administración.

**Evidencia.** `E2E_CHROME_RESULTS.md` §1 y §5; `browser_product.txt`;
`branded_chrome_load_extension.log`.

---

## L11. `extension.pem`: clave de firmado preexistente en el repositorio (revisión de credenciales, B‑09/C‑4)

**Qué.** El barrido de secretos a árbol completo (`scripts/_secret_scan_before_commit.py`,
condición C‑4) clasifica `extension.pem` como `PREEXISTING_DOCUMENTED`: es la
**clave privada de firmado de la extensión Chrome**, ya rastreada en git **antes**
de esta fase (no es un secret introducido por la fase de corrección) y reportada
en cada barrido, nunca silenciada.

**Por qué no se borró en esta fase.** Eliminarla del árbol (o reescribir la
historia de git) exige **rotar la clave** y regenerar la firma de la extensión,
lo que es una operación destructiva que requiere aprobación explícita; hacerlo
de forma silenciosa rompería la trazabilidad de los commits anteriores.

**Impacto.** Cualquier persona con acceso al repositorio dispone de la clave de
firmado de la extensión; la extensión distribuida podría firmarse con ella.
Para una extensión en fase de investigación (no publicada en la Chrome Web
Store) el riesgo es bajo, pero **no es cero**.

**Recomendación.** (1) Rotar la clave (`extension.pem`) y regenerar la firma
antes de cualquier publicación; (2) retirarla del historial de git con
`git filter-repo` + reescritura de remoto, operación que queda **pendiente de
aprobación**; (3) mantener el secretos-scan obligatorio previo a cada commit
(documentado en `REPRODUCIBILIDAD.md`).

---

## L12. Dos rutas de producto desactivan o evitan la verificación TLS (preexistentes; fuera del alcance de C‑3)

**Qué.** La condición C‑3 de la auditoría técnica estaba acotada a
`src/phishguard_api/llm_agent.py` (fallback `verify_ssl = False` ante `SSLError`,
ya eliminado y cubierto por pruebas de regresión). El barrido de esta fase
detectó, además, **dos desactivaciones de verificación preexistentes** en el
código base que **no** se modifican en esta fase para no alterar el
comportamiento del servicio ya evaluado:

1. `src/phishguard_api/server.py` — la adquisición de contenido usa
   `requests.get(job.url, verify=False, ...)` con `urllib3.disable_warnings(...)`:
   se aceptan certificados inválidos al descargar la página a analizar.
2. `src/phishguard_ml/detection_rules.py` — `_check_server_geolocation` crea un
   contexto `ssl` con `check_hostname=False` / `CERT_NONE` y consulta la API de
   geolocalización por **`http://` plano** (el contexto ni siquiera se usa: la
   URL no es HTTPS).

**Por qué no se corrigió aquí.** Ambas rutas pertenecen a la configuración
original (commit base `ceb0c9e`); cambiarlas modificaría la adquisición de
modalidades y la ruta de reglas, con efecto sobre métricas ya congeladas que
exigiría una re-validación completa. C‑3 se cerró en su alcance literal.

**Impacto.** Riesgo MITM en la descarga de contenido (páginas servidas o
alteradas por un intermediario) y fuga de la IP/consultas del analizador hacia
`ip-api.com` sin cifrar. No afecta a los modelos congelados ni a las métricas
publicadas.

**Recomendación.** Habilitar `verify=True` con manejo explícito de `SSLError`
(distinto para hosts legítimos con certificados rotos que para phishing),
migrar la geolocalización a HTTPS con contexto por defecto, y cubrir ambos
cambios con pruebas de regresión en una fase posterior.

---

## Resumen de lo que SÍ queda demostrado con evidencia archivada

| Afirmación | Evidencia |
|---|---|
| BUG-01…BUG-08 corregidos | `MATRIZ_TRAZABILIDAD_FINAL.csv` (con SHA-256 por archivo) + 186 pruebas, 0 fallos |
| El defecto BUG-03 (Punycode) está resuelto sin falsos positivos | `manual_audit_regressions.json` (PASS + controles negativos) |
| El defecto BUG-04 (umbral de abstención) gobierna la decisión | Barrido 0.01/0.20/0.99 → 119/119/12 abstenciones con `decide_next()` real sobre datos externos |
| El defecto BUG-07 (`www`) está resuelto | Experimento pareado N = 300: FPR 100 % → 5.33 %, 170/300 → 0/300 discordancias |
| La regresión BUG-08 (Levenshtein) detectada en esta fase está corregida | 15 pruebas vs implementación de referencia + disparadores legítimos 1 → 0 |
| Resultados históricos reproducibles | 14/14 filas del CSV de pruebas pareadas recomputadas exactamente |
| Validación externa independiente ≥ 1 000 URLs | Cohorte2 N = 1 200 congelada, sin solape, congelada antes de consultar etiquetas |
