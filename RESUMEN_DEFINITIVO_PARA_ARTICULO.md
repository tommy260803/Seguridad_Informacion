# RESUMEN DEFINITIVO PARA ARTÍCULO — PhishPe (PhishGuard) corregido

**Versión:** 2026‑10‑14 (UTC) · rama `corrections-phase2` · congelación vigente
`0999ef95922262a6b796cf1dc2aa5515c095f47d179bf7945ba327ee78d92c41`

> **Nota de retiro de cifras previas.** Este resumen sustituye íntegramente a la
> versión anterior, que contenía cifras no sustentables («cohorte de 23 URLs»,
> «127/127 pruebas», «FPR externo 46,70 % → 9,69 %» obtenida sobre la cohorte
> rechazada, «M5 = 0,9538», «LLM 7/29 evaluadas»). Todas las cifras de este
> documento son **recomputadas desde artefactos con SHA‑256** y se generan
> programáticamente con `scripts/phase2h_build_deliverables.py`.

---

## 1. Contribuciones demostradas con evidencia archivada

1. **Corrección y verificación de 8 defectos** (los 7 de la auditoría previa más
   uno —BUG‑08— detectado y corregido en esta fase), cada uno con prueba de
   regresión, evidencia archivada y SHA‑256 en `MATRIZ_TRAZABILIDAD_FINAL.csv`:
   BUG‑01 timeout 8 000 ms · BUG‑02 DNS en `asyncio.to_thread` · BUG‑03
   decodificación Punycode etiqueta a etiqueta · BUG‑04 umbral de abstención
   final separado · BUG‑05 sin etapa visual forzada · BUG‑06 mezcla LLM
   `0.7/0.3` · BUG‑07 `_strip_www()` · BUG‑08 DP de Levenshtein reparada.

2. **Validación externa independiente con una cohorte nueva de N = 1 200 URLs**
   (600 phishing / 600 legítimas) de PhishTank, URLhaus, OpenPhish, Tranco y
   Majestic, **sin solape** con el corpus interno (176 201 URLs / 130 047
   dominios registrados) ni con la cohorte externa previa (1 054 URLs),
   **congelada antes de consultar las etiquetas** y con todos los descartes
   publicados con su motivo.

3. **Reproducción experimental de los dos defectos que la auditoría probó a
   mano**, ahora correctos y con archivo de evidencia
   (`manual_audit_regressions.json`, `overall_PASS = true`).

4. **E2E en Chrome real** (navegador del sistema, extensión empaquetada, backend
   real, red real, sin ASGI ni mocks como prueba principal):
   `E2E_CHROME_RESULTS.md` + `artifacts/e2e_chrome/`.

5. **Reconciliación de reproducibilidad al 100 %**: 14/14 filas del CSV de
   pruebas pareadas históricas recomputadas exactamente; corrección de las
   discrepancias texto‑vs‑CSV, de las fechas erróneas («2026‑04‑12» →
   2026‑10‑12) y retirada de la cifra no sustentable de 105 541 dominios.

6. **174 pruebas automatizadas, 0 fallos** (47 de regresión de defectos), con
   XML de junit archivado.

---

## 2. Resultados principales (cohorte2, N = 1 200)

| Brazo | F1 | FPR | FNR |
|---|---:|---:|---:|
| M0 original (sin normalización) | 0,8829 | 3,33 % | 18,33 % |
| M0 normalizado (`strip_www`) | 0,8707 | 3,33 % | 20,33 % |
| Config A (extensión original) | 0,8593 | 0,67 % | 24,17 % |
| Config C (extensión corregida) | 0,8550 | 0,67 % | 24,83 % |

**Experimento pareado `www`/no‑`www` (N = 300 dominios legítimos × 2 variantes)**
— la medición decisiva del BUG‑07:

| | Sin normalizar | Normalizado |
|---|---:|---:|
| FPR en legítimos con `www` | **100,00 %** | **5,33 %** |
| Pares con decisiones discordantes | **170/300** | **0/300** |

**Sondeo vivo N = 600** (ITE vs complete‑case, abstenciones nunca contadas como
aciertos): completitud 13,3 % phishing vs 69,0 % legítima → los complete‑case
**no son representativos**; con estrategia de fallback a M0,
F1 = 0,8246 / FPR = 5,00 % / FNR = 26,33 %; latencias reales de pared
infra p50 = 959 ms, p95 = 3 577 ms.

**Cascadas externas**: M2 0,8404 (cobertura 1,0) · M5 selectivo 0,8743 (cobertura
0,8717, 77 abstenciones) · conservadora 0,8725 · Config C corregida 0,8680
(cobertura 0,8017, 119 abstenciones). Ninguna diferencia significativa frente a
M2 (McNemar p ≥ 0,53). Barrido del umbral de abstención 0,01/0,20/0,99 →
**119/119/12 abstenciones**: el umbral gobierna de verdad la decisión.

**Resultados internos recomputados (N = 691)**: M0 0,8658 · M1 0,9252 ·
M2 0,9315 · M3 0,9286 · M4 0,9248 — **Δ = 0,0000 frente a los valores
históricos**, lo que demuestra que los pesos no cambiaron (los fixes son de
inferencia y política).

---

## 3. Resultado negativo que debe publicarse (intercambio medido)

La corrección del atajo `www` **está probada que resuelve el defecto** (FPR
100 % → 5,33 % en el experimento pareado), pero **con los pesos congelados sin
reentrenar** cuesta 12 detecciones de phishing en la cohorte externa natural
(F1 0,8829 → 0,8707; McNemar 12 discordantes todas favorables al original,
p = 0,000488; Holm p = 0,001465). En la Config A vs C la diferencia es de 4
pares discordantes y **no es significativa** (p = 0,125; Holm p = 0,25).

**Interpretación para el artículo**: se elimina un falso positivo masivo
potencial (cualquier legítimo con `www`) a cambio de un coste de recall sobre
hosts `www` que desaparecerá al **reentrenar M0 con características
normalizadas** (recomendación §5.1). No se afirma mejora neta de F1.

---

## 4. Afirmaciones que NO deben incluirse en el artículo

1. **No** se afirma mejora del F1 interno: es exactamente 0,0000 por diseño.
2. **No** se afirma que la Config C sea superior a la A: la diferencia no es
   significativa (p Holm = 0,25) e incluso favorece ligeramente a la A en F1.
3. **No** se afirma que la cascada mejore a M2 en datos externos: p ≥ 0,53.
4. **No** se afirma que el blend con LLM esté validado end‑to‑end: solo por
   prueba de código (la API de pago no está autorizada).
5. **No** se usa la cifra «105 541 dominios únicos» (retirada; ver
   `REPRODUCIBILIDAD.md` §R2) ni «FPR externo 46,70 % → 9,69 %» (perteneciente
   a la cohorte rechazada de 1 054 URLs, no a esta fase).
6. **No** se declara la cohorte de acortadores como validación (N = 16,
   suplementaria y post‑hoc).
7. **No** se declara que «todo está corregido»: quedan 9 limitaciones
   documentadas en `LIMITACIONES_RESTANTES.md`.

---

## 5. Recomendaciones

1. **Reentrenar M0 con características normalizadas** (eliminar el atajo `www`)
   para recuperar el recall sin reabrir el falso positivo.
2. **Añadir un estrato de acortadores** con etiqueta de destino final.
3. **Capturas CDP auténticas en el sondeo externo** para cerrar la evaluación de
   la modalidad visual.
4. **Evaluación del blend LLM** con modelo local o API autorizada.
5. Para diferencias pequeñas entre políticas, **cohortes ≥ 10 000 URLs**.

---

## 6. Tablas y figuras recomendadas para el artículo

| Elemento | Fuente (recomputable) |
|---|---|
| Tabla 1 — Antes/después por defecto | `COMPARACION_ANTES_DESPUES.csv` (20 filas, columna de métrica explícita) |
| Tabla 2 — Trazabilidad defecto→prueba→evidencia→SHA‑256 | `MATRIZ_TRAZABILIDAD_FINAL.csv` (8 defectos) |
| Tabla 3 — Comprobaciones automáticas PASS/FAIL | `VALIDACION_FINAL_AUTOMATICA.json` (12 comprobaciones, 8 registros de defecto) |
| Tabla 4 — Modelos y umbrales congelados (SHA‑256, nº de características, umbral) | `REPRODUCIBILIDAD.md` §7 |
| Figura 1 — FPR en legítimos con/sin `www` (experimento pareado) | `www_paired_experiment.json` |
| Figura 2 — Curva cobertura–riesgo de las cascadas externas | `probe_and_cascade_metrics.json` |
| Figura 3 — Barrido del umbral de abstención (0,01 / 0,20 / 0,99) | `probe_and_cascade_metrics.json → sensibilidad_abstention_threshold_BUG04` |

---

## 7. Resumen ejecutivo (para la versión final del artículo)

PhishPe fue corregido, congelado y validado de forma independiente. Se
corrigieron ocho defectos de ingeniería —entre ellos dos que la validación
externa expuso durante la propia fase (una regresión de Levenshtein que marcaba
acortadores legítimos como suplantación de marca, y un defecto del script de
medición de la cascada)— y cada corrección está respaldada por pruebas de
regresión, experimentos reproducibles y hashes SHA‑256. La validación externa se
ejecutó sobre una cohorte nueva e independiente de 1 200 URLs congelada antes de
consultar etiquetas, con la mortalidad de URLs declarada y separada por clase, y
con las abstenciones excluidas del denominador de aciertos. El hallazgo central
para el artículo es un **intercambio medido y publicable**: la normalización
`www` elimina por completo un falso positivo sistemático (100 % → 5,3 % en el
experimento pareado) a costa de un coste de recall de 12 detecciones que se
recuperará reentrenando el modelo, y las mejoras de cascada observadas externamente
**no son significativas**, lo que fija con honestidad el estado del arte del
sistema y sus límites de generalización.
