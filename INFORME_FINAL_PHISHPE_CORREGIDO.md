# INFORME FINAL — PhishPe (PhishGuard) CORREGIDO

**Fecha:** 2026-10-14 (UTC)
**Rama:** `corrections-phase2` (desde `experimental/validacion-scopus-fase2`)
**Commit base congelado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`
**Congelación vigente (freeze #3):** `0999ef95922262a6b796cf1dc2aa5515c095f47d179bf7945ba327ee78d92c41`
**Semilla determinista:** `SEED = 42`

---

## 0. Dictamen

La fase de corrección **cierra los 8 defectos** (los 7 de la auditoría previa más
uno —BUG-08— detectado y corregido durante esta misma fase), con:

- **174 pruebas automatizadas, 0 fallos** (47 de ellas de regresión de los
  defectos; evidencia: `artifacts/corrections_phase2/junit_full_suite.xml`).
- **Una segunda cohorte externa independiente de N = 1,200 URLs** (600 phishing
  + 600 legítimas), construida con etiquetas de PhishTank, URLhaus, OpenPhish,
  Tranco y Majestic, **sin solape** con el corpus interno (176,201 URLs /
  130,047 dominios registrados) ni con la cohorte externa previa (1,054 URLs),
  **congelada antes de consultar las etiquetas**.
- **Experimentos que reproducen exactamente los dos defectos que la auditoría
  probó a mano**, ahora con resultado correcto y archivo de evidencia.
- **E2E en Chrome real** (navegador del sistema, extensión empaquetada, backend
  real, red real): `E2E_CHROME_RESULTS.md` + `artifacts/e2e_chrome/`.
- **Reconciliación al 100 %** de las estadísticas históricas (14/14 filas del
  CSV de pruebas pareadas recomputadas exactamente) y corrección de las
  discrepancias texto‑vs‑CSV, fechas erróneas y cifra no sustentable.

**Hallazgo científico honesto que debe publicarse:** la corrección del atajo de
`www` (BUG‑07) está **probada que resuelve el defecto** (experimento pareado:
FPR en legítimos con `www` del **100 % → 5,33 %**; 170/300 pares con decisiones
discordantes → **0/300**), pero como los pesos de M0 **no se reentrenaron**
(congelados por protocolo), en la cohorte externa natural la normalización cuesta
12 detecciones de phishing (F1 0,8829 → 0,8707; McNemar p = 0,000488). Es un
**intercambio medido y documentado**: se elimina un falso positivo masivo
potencial a cambio de un coste de recall sobre hosts `www` que desaparecerá al
reentrenar M0 con características normalizadas (recomendación §6).

---

## 1. Qué se corrigió y con qué evidencia

La tabla completa, con el SHA‑256 del archivo de evidencia de cada defecto, está
en `MATRIZ_TRAZABILIDAD_FINAL.csv`. Resumen:

| ID | Defecto | Corrección | Cómo se prueba que está resuelto |
|---|---|---|---|
| BUG‑01 | Timeout de cliente 4 000 ms abortaba páginas legítimas lentas | Presupuesto a **8 000 ms** | 3 pruebas (servidor lento de 6 s) + escenarios E2E Chrome (timeout, offline) |
| BUG‑02 | `socket.getaddrinfo` bloqueante congelaba el bucle de eventos | Movido a `asyncio.to_thread` | 4 pruebas, incluida una de vivacidad del bucle con DNS retrasado 3 s |
| BUG‑03 | Punycode `xn--pple-43d` no se decodificaba (el regex perdía guiones) → **evadía** la detección de homógrafos | Decodificado **etiqueta a etiqueta** + comparación `punycode_to_unicode(dominio registrado)` vs dominio oficial | **Caso exacto de la auditoría**: `is_spoofing` False → **True**; 12 pruebas + 5 controles negativos en False |
| BUG‑04 | El motor ignoraba `abstention_threshold` final (usaba `uncertainty_threshold`) | Umbral de abstención final **separado** en `decide_next` | **Caso exacto de la auditoría** (0,01/0,99 cambian la decisión) + **barrido sobre datos externos**: 119/119/12 abstenciones |
| BUG‑05 | El orquestador **forzaba** la etapa visual sin M3 | `force_visual` eliminado; modalidad no disponible → fallback | 2 pruebas + cascada externa sin `no_available_modality` silenciosos |
| BUG‑06 | El resultado del LLM **sobrescribía** la probabilidad de la cascada | Mezcla explícita `0.7·p + 0.3·llm` | 3 pruebas (evaluación con LLM de pago **no autorizada**: limitación L2) |
| BUG‑07 | Sin normalización de `www`, un host legítimo `www` era clasificado phishing (atajo aprendido) | `_strip_www()` en la canalización | **Experimento pareado N = 300**: FPR 100 % → 5,33 %; discordancias 170/300 → 0/300 |
| BUG‑08 | **Nuevo, detectado aquí**: la DP de Levenshtein tenía `previous_row = current_row` fuera del bucle externo → `lev('t','microsoft') = 0` → `t.ly`, `t.is`, `s.id` se marcaban como «suplantación de Microsoft/PayPal» (prob. 0,99) | Asignación devuelta al interior del bucle + comentario | 15 pruebas contra implementación de referencia; disparadores legítimos de homógrafos 1 → **0** |

> **Nota sobre BUG‑08.** El commit base `ceb0c9e` tenía la asignación en la
> posición correcta: la regresión se introdujo en el árbol de trabajo de esta
> fase y fue **el propio proceso de validación externa la que la detectó** al
> auditar los 36 disparadores de la ruta crítica de homógrafos sobre la cohorte2
> (1 de ellos legítimo e injustificado). Se corrigió antes de congelar el estado
> definitivo (freeze #3). Queda registrado en
> `artifacts/corrections_phase2/FREEZE_HISTORY.md`.

---

## 2. Protocolo experimental (congelar → etiquetar → evaluar)

1. **`phase2a_freeze.py`**: congeló 98 archivos de código (`src/` + `extension/`),
   9 modelos (SHA‑256, umbral, nº de características), 10 snapshots del código
   original del commit base (Config A) y los umbrales/políticas. Cualquier
   desviación posterior **aborta** la evaluación.
2. **`phase2b_acquire_cohort2.py`**: construyó la cohorte2 con fuentes reales,
   determinista (semilla 42), registrando **todos** los candidatos y los
   excluidos con motivo por fila.
3. **`phase2c_evaluate_cohort2.py`**: evaluación por bloques (URL‑level,
   sondeo vivo, cascadas, recomputación interna, experimento pareado `www`).
4. **`phase2d`**, **`phase2e`**, **`phase2g`**, **`phase2i`**: mediciones
   complementarias que no tocan modelos ni etiquetas.

Hubo **tres congelaciones** (historial íntegro en
`artifacts/corrections_phase2/FREEZE_HISTORY.md`): la inicial antes de consultar
etiquetas; una segunda por un defecto del **propio script de medición** de la
Config C (no descontaba presupuesto ni trataba la ausencia de M3); y la tercera
por BUG‑08. **Ninguna alteró modelos ni umbrales** (verificado comparando los
bloques `models` y `thresholds_and_normalization` de los manifiestos).

**Cohorte2 congelada** (`cohort2_dataset.csv`, SHA‑256
`bb8f6284a6779a98cb4a3bec65eaac86f15dfa196713358129535bd131e32f73`):

| | |
|---|---:|
| N total | **1 200** (600 phishing / 600 legítimas) |
| Fuentes | urlhaus 297, tranco 389, phishtank 260, majestic 211, openphish 43 |
| Solape con corpus interno | **0** URLs y **0** dominios registrados (verificado contra 176 201 URLs / 130 047 dominios) |
| Solape con cohorte externa previa | **0** |
| Estratos | con `www` 21 · IDN/punycode 43 · con subdominio 542 · con ruta 404 · con parámetros 25 · host‑IP 230 · acortadores 0 |
| Excluidos (con motivo) | `cohort2_excluded.csv` |

---

## 3. Resultados de la validación externa (cohorte2, N = 1 200)

### 3.1 Nivel de URL (brazos A/B)

| Brazo | F1 | FPR | FNR | Precisión | Recall |
|---|---:|---:|---:|---:|---:|
| M0 **original** (sin normalización) | 0,8829 | 3,33 % | 18,33 % | 0,9608 | 0,8167 |
| M0 **normalizado** (`strip_www`) | 0,8707 | 3,33 % | 20,33 % | 0,9598 | 0,7967 |
| Config **A** (extensión original) | 0,8593 | 0,67 % | 24,17 % | 0,9913 | 0,7583 |
| Config **C** (extensión corregida) | 0,8550 | 0,67 % | 24,83 % | 0,9912 | 0,7517 |

- **M0 normalizado vs original**: 12 pares discordantes, **todos** favorables al
  original (McNemar exacto p = 0,000488; Holm p = 0,001465). Las 12 son URLs
  phishing **con `www`** (21 en toda la cohorte; 0 legítimas con `www`). Es el
  coste documentado de quitar el atajo sin reentrenar (§0, L1).
- **Config A vs C**: 4 pares discordantes (p = 0,125; Holm p = 0,25) — **no
  significativo**. Tras corregir BUG‑08, la Config C **iguala** el FPR de la A.
- **Disparadores de la ruta crítica de homógrafos**: A = 1 → **C = 7, todos
  phishing, 0 legítimos** (antes de corregir BUG‑08 eran 36 con 1 legítimo
  injustificado).

### 3.2 Experimento pareado `www`/no‑`www` (el defecto BUG‑07, medido de verdad)

Como la cohorte natural solo tiene 21 URLs con `www` (todas phishing), se
construyó un **experimento pareado**: 300 dominios legítimos × 2 variantes
(con y sin `www`), 600 evaluaciones.

| | Sin normalizar | Normalizado |
|---|---:|---:|
| FPR en legítimos **con** `www` | **100,00 %** (150/150) | **5,33 %** |
| FPR en legítimos **sin** `www` | 5,33 % | 5,33 % |
| Pares con decisiones discordantes (misma URL, solo cambia `www`) | **170/300** | **0/300** |
| Desplazamiento máximo de probabilidad | 0,9787 | — |

**Conclusión**: sin `_strip_www()`, **cualquier** dominio legítimo con `www` se
clasificaba phishing; con la corrección, la variante `www` y la no‑`www`
producen **exactamente la misma decisión**.

### 3.3 Sondeo vivo (N = 600) — intention‑to‑evaluate vs complete‑case

La mortalidad de URLs **no es aleatoria** (completitud 13,3 % phishing vs
69,0 % legítimas), por lo que ambos denominadores se reportan por separado y
**las abstenciones nunca cuentan como aciertos**:

| Denominador | M0 | M1 | M2 |
|---|---:|---:|---:|
| *Complete‑case* (N = 247) | F1 0,6977 / FPR 7,73 % | F1 0,7397 | F1 0,7273 |
| *Intention‑to‑evaluate* (N = 600, fallback a M0 si falta modalidad) | F1 0,8246 / **FPR 5,00 %** / FNR 26,33 % | — | — |

Latencias **reales de pared** (no sumas de medianas): infraestructura
(DNS+TLS+HTTP) p50 = 959 ms, p95 = 3 577 ms; descarga HTTP p50 = 860 ms,
p95 = 3 838 ms; sondeo completo de 600 URLs = 57,4 s.

### 3.4 Cascadas sobre el sondeo externo

| Política | F1 (decididos) | FPR | Cobertura | Abstenciones |
|---|---:|---:|---:|---:|
| M2 sin cascada | 0,8404 | 18,67 % | 1,0000 | 0 |
| M4 original forzada (parada temprana) | — | — | 1,0000 | 0 |
| **M5 selectivo** | 0,8743 | 8,71 % | 0,8717 | 77 (41 ph / 36 leg) |
| Conservadora (M1 obligatorio) | 0,8725 | 9,09 % | 0,8717 | 77 |
| **Config C corregida (BUG‑04)** | 0,8680 | 6,94 % | 0,8017 | 119 (64 ph / 55 leg) |

McNemar pareado contra M2: conservadora p = 0,5966; Config C p = 0,5327 —
**ninguna diferencia significativa** (L6). La Config C corregida muestra
además la métrica completa con la abstención contada como positivo
(F1 = 0,8190) para no inflar el resultado selectivo.

**Barrido del umbral de abstención sobre datos externos** (la prueba exacta que
exigió la auditoría, ejecutada con `decide_next()` real):

| `abstention_threshold` | Abstenciones | Cobertura | F1 decididos |
|---:|---:|---:|---:|
| 0,01 | 119 | 0,8017 | 0,8680 |
| 0,20 (defecto) | 119 | 0,8017 | 0,8680 |
| 0,99 | 12 | 0,9800 | 0,8453 |

`assertion_threshold_has_effect = true`: el umbral **gobierna** la decisión
(anteriormente el motor devolvía lo mismo con cualquier valor).

---

## 4. Resultados internos recomputados (prueba de que los pesos no cambiaron)

Recomputados desde los `predictions.csv` congelados del particionado de prueba
(N = 691; 191 phishing / 500 legítimas):

| Modelo | F1 | FPR | FNR | Valor histórico | Δ |
|---|---:|---:|---:|---:|---:|
| M0 | 0,8658 | 3,20 % | 17,28 % | 0,8658 | **0,0000** |
| M1 | 0,9252 | 0,60 % | 12,57 % | 0,9252 | **0,0000** |
| M2 | 0,9315 | 0,80 % | 10,99 % | 0,9315 | **0,0000** |
| M3 | 0,9286 | 0,80 % | 11,52 % | 0,9286 | **0,0000** |
| M4 | 0,9248 | 0,40 % | 13,09 % | 0,9248 | **0,0000** |

Δ = 0 confirma que **las correcciones son de inferencia y política, no de
entrenamiento**: los modelos publicados son los mismos.

---

## 5. Reproducibilidad y reconciliación (§9 del acta)

El detalle completo está en `REPRODUCIBILIDAD.md`. Lo esencial:

| Punto de la auditoría | Resolución | Evidencia |
|---|---|---|
| Fechas «2026‑04‑12» vs. octubre 2026 | Error tipográfico; ejecución real **2026‑10‑12** (commits 29‑sep…6‑oct, `captured_at` 12‑oct) | 3 informes corregidos con nota |
| «105 541 dominios únicos» | Cifra **retirada**; real: **130 047** dominios registrados / 141 247 hosts / 176 201 URLs; las 105 541 eran un recuento de legítimas inconsistente (105 541 + 76 207 = 181 748 ≠ 176 201) | Recomputación desde `samples.csv` (SHA‑256 `947350f0…`) |
| Texto del informe 07 vs su CSV | **El CSV era correcto (14/14 reproducidas)**; se corrigió el texto (E1: +0,0127 → **+0,006299**, 9/4 → **8/6**, p 0,2668 → **0,7905**; E2: −0,0007 → **−0,002935**) | `historical_stats_reconciliation.json` (`PASS`) + nota de corrección en el informe 07 |
| Faltaban candidatos excluidos y scripts | Publicados `cohort2_candidates_all.csv`, `cohort2_excluded.csv` (motivo por fila) y los scripts `phase2a`–`phase2i` | Carpeta `artifacts/corrections_phase2/cohort2/` |
| Dependencias no documentadas | `requirements-lock.txt` (335 versiones), PSL, Tranco, marcas, Chrome, Playwright | §R5 de `REPRODUCIBILIDAD.md` |
| Chrome real vs ASGI | Batería E2E en **Chrome real** con extensión empaquetada y backend real | `E2E_CHROME_RESULTS.md` + `artifacts/e2e_chrome/` |
| Modelos/umbrales sin identificar | Tabla con SHA‑256, nº de características, umbral y candidato de los 9 modelos + política congelada | §R7 de `REPRODUCIBILIDAD.md` |

---

## 6. Recomendaciones derivadas (para el artículo)

1. **Reentrenar M0 con características normalizadas** (sin el atajo `www`) para
   recuperar el recall en hosts `www` sin reabrir el falso positivo (L1).
2. **Ampliar la cohorte con un estrato de acortadores etiquetado** por destino
   final (L4).
3. **Añadir capturas CDP auténticas al sondeo externo** para cerrar la
   evaluación de la modalidad visual (L5).
4. **Evaluación del blend LLM** con modelo local o API autorizada (L2).
5. Para diferencias pequeñas entre políticas, **cohortes ≥ 10 000 URLs** (L6).

---

## 7. Paquete de evidencia

`evidencia_phishpe_definitiva.zip` (SHA‑256 publicado junto al entregable)
contiene, sin excepción, los archivos citados: congelaciones y su historial,
cohorte2 completa (candidatos, excluidos, dataset, etiquetas), todas las salidas
de `phase2a`–`phase2i`, el XML de las 174 pruebas, la verificación manual de los
defectos de la auditoría, la reconciliación histórica, los entregables
generados programáticamente y los resultados E2E de Chrome.

**Ninguna cifra de este informe está escrita a mano**: los tres entregables
cuantitativos (`COMPARACION_ANTES_DESPUES.csv`,
`MATRIZ_TRAZABILIDAD_FINAL.csv`, `VALIDACION_FINAL_AUTOMATICA.json`) se
generan con `scripts/phase2h_build_deliverables.py` directamente desde los
artefactos, y el JSON de validación comprueba además que el número de
comprobaciones coincide con el número de registros.
