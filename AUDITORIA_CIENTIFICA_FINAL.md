# AUDITORÍA CIENTÍFICA FINAL — Proyecto PhishPe / PhishGuard

**Fecha:** 2026-10-14 · **Auditoría independiente de fase final (adversarial)**
**Repositorio:** `D:\Proyects\Seguridad_Informacion` · **Rama:** `corrections-phase2`
**Commit auditado:** `96944d4632cbefdae5b0341d72165fa1e96cbc07` · **Base inmutable:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`
**Árbol de trabajo:** limpio (`git status --porcelain` vacío) al inicio y al final de la auditoría.

---

## 1. Alcance y método

Auditoría de 10 verificaciones obligatorias con respaldo en archivos (V1–V10), más
dos verificaciones de reproducibilidad (T-01, R-01). Cada cifra de los entregables
fue **recomputada de forma independiente** con scripts propios de la auditoría
(ubicados fuera del repositorio, en
`C:\Users\User\AppData\Local\Temp\opencode\phishpe_audit\`), no citada de los
informes. Las afirmaciones de los informes se contrastaron contra los datos de
origen (CSV, JSON, JSONL, manifiestos de hash); **la ausencia de aprobación se
declara como tal**.

Garantías de integridad de la auditoría:

- La auditoría **no modificó ningún archivo del repositorio**. El único archivo
  creado es este informe. No se escribió nada en `artifacts/`.
- `scripts/phase2h_build_deliverables.py` se ejecutó como prueba de
  determinismo; el único cambio producido fue el campo `generated_utc`
  (capturado con `git diff` y **revertido** con `git checkout --`); los dos CSV
  resultaron byte-idénticos.
- `python -m pytest tests/ -q` se ejecutó con JUnit XML fuera del repositorio
  (`%TEMP%\phishpe_audit_junit.xml`).
- Las verificaciones que implicaban reescribir artefactos
  (`phase2k_summarize_e2e.py`) **no** se re-ejecutaron: sus cifras se
  recomputaron en memoria desde `requests.jsonl` + `summary.json` con el mismo
  algoritmo que el script (filtro `localhost:8080`, deduplicación de
  resource-timing por `(name, start)`, percentiles `_pct`).

---

## 2. Tabla de verificaciones

| ID | Afirmación auditada | Verificación independiente | Resultado | Evidencia |
|---|---|---|---|---|
| **V1** | El congelamiento (freeze #3) fija hashes verificables de código, modelos y scripts | SHA-256 del manifiesto = `0999ef95922262a6b796cf1dc2aa5515c095f47d179bf7945ba327ee78d92c41`, idéntico en `FREEZE_HISTORY.md` (#3), `phase2a_refreeze3.log`, `eval_summary.json` y la copia dentro de `evidencia_phishpe_definitiva.zip`. 9/9 modelos hash+bytes correctos (m4/m5 declarados ausentes y realmente ausentes); 10/10 snapshots baseline; 98/98 `corrected_code_sha256` | **CON OBSERVACIÓN (MAYOR-1)** | `artifacts/corrections_phase2/freeze_manifest.json`; `scripts/phase2c_evaluate_cohort2.py:83-108` |
| **V2** | La cohorte externa nueva (N = 1,200) es independiente, equilibrada y congelada antes de etiquetar | SHA-256 `bb8f6284…` coincide con el declarado; N = 1200 (600/600); por fuente {urlhaus 297, phishtank 260, openphish 43, majestic 211, tranco 389}; sin dominios duplicados; **solape 0 dominios / 0 URLs** contra `samples.csv` (176,201 URLs / 130,047 dominios) y **0** contra la cohorte previa de 1,054 (recomputado con PSL); `labels_frozen` 03:25:00 posterior al freeze #1 03:15:30; justificación de tamaño escrita antes de descargar feeds | **APTO (obs. MENOR-1)** | `artifacts/validacion_scopus_fase2/fase2_externa/external_validation_dataset_n1200.csv`; `scripts/phase2b_acquire_cohort2.py` |
| **V3** | Las 14 pruebas pareadas de hipótesis son exactamente reproducibles | SHA-256 del CSV = `73f77123…` (coincide con el declarado); **14/14 p-values de McNemar exacto recomputados** e idénticos al CSV (incl. `M0_decided_vs_M5_selective` 1.907348633e-06 vs 1.91e-06 = redondeo); χ² con corrección de continuidad y sumas de celdas correctas; Holm paso a paso correcto en ambas familias (H m=6, E m=8). **Pero el informe `07_ANALISIS_ESTADISTICO.md` discrepa del CSV canónico en 5/14 filas** | **NO APTO PARCIAL (MAYOR-2)** | `artifacts/validacion_scopus_fase2/fase7_estadistica/07_all_hypothesis_tests_table.csv:4,13,14`; `07_ANALISIS_ESTADISTICO.md:89,100,101,103,104` |
| **V4** | Las abstenciones y la mortalidad de URLs no se contabilizan como aciertos | Verificado en código: abstención → positiva solo en `metrics_full_coverage_abstain_as_positive` (`phase2c_evaluate_cohort2.py:472-474`), métricas selectivas aparte con `dec ≈ ~c_abst` (538-557), nota explícita en `politicas_sobre_abstenciones` (589-594), bloque ITE vs `complete_case` con advertencia "NO representan a los N intentos" (614-693). Aritmética de 119/64/55 y 481 consistente | **APTO** | `scripts/phase2c_evaluate_cohort2.py:472-700` |
| **V5** | Cada defecto BUG-01…08 tiene evidencia archivada con hash real | 20 filas en `COMPARACION_ANTES_DESPUES.csv`; hashes SHA-256 reales y verificados de los 8 `defect_fix_records` (tests `6b10be01…`, manual_audit `f06904d6…`, probe `543d0432…`, www `8ee06117…`); `MATRIZ_TRAZABILIDAD_FINAL.csv` hashes idénticos; bug03 `homoglyph_critical_path_triggers` A=1 / C=7; www pareado 1.0 → 0.053333 y 170/300 → 0/300; barrido 119/119/12; Config A 0.859301 vs C 0.854976 | **APTO** | `MATRIZ_TRAZABILIDAD_FINAL.csv`; `artifacts/corrections_phase2/eval/*.json` |
| **V6** | `VALIDACION_FINAL_AUTOMATICA.json` certifica el estado | 12/12 PASS; las 12 rutas de evidencia existen; `checks == len(checks)` y registros = 8 coherentes; T-01 (abajo) confirma 174 pruebas. **Pero el bloque `freeze` es nulo** (`manifest_sha256`, `git_commit`, `dirty` = `null`) | **APTO CON OBS. (MENOR-2)** | `VALIDACION_FINAL_AUTOMATICA.json`; `scripts/phase2h_build_deliverables.py:417` |
| **V7** | La batería E2E corrió en Chrome real y sus cifras son reproducibles | Recomputado desde `summary.json` + `requests.jsonl`: 27 escenarios = **25 PASS / 2 NOT_RUN** (`l_concurrency`, `o_cascade_analyses`); 40 llamadas al backend (40/40 con filtro `localhost:8080`; las 6 restantes de `api_new` son a `ipwho.is`, geolocalización, excluidas correctamente); **4 errores, todos deliberados** (8010/8004 ms timeout, 2 caídas de backend), **0 espontáneos**; los 4 bloques de percentiles (cliente, resource-timing, nav→insignia, nav→decisión) **recomputados idénticos** al declarado; 54 PNG; `Chrome/156.0.8078.4` (CfT) vs marca `155.0.8059.40` con rechazo literal de `--load-extension` | **APTO** | `artifacts/e2e_chrome/summary.json`, `requests.jsonl`, `chrome_version.txt`, `branded_chrome_load_extension.log`; `E2E_CHROME_RESULTS.md` |
| **V8** | El coste del BUG-07 (reentrenamiento no hecho) se declara con honestidad | Presente en `INFORME_FINAL_PHISHPE_CORREGIDO.md` §0 (líneas 31-39: "intercambio medido… coste de recall… que desaparecerá al reentrenar M0"), §3.1 (líneas 115-118: 12 discordantes todas contra la normalización, p = 0.000488) y §6 (recomendación 1: reentrenar M0). En `RESUMEN_DEFINITIVO_PARA_ARTICULO.md` §3 (líneas 86-98: "Resultado negativo que debe publicarse… **No se afirma mejora neta de F1**") y §4 | **APTO** | `INFORME_FINAL_PHISHPE_CORREGIDO.md:31-39,115-118,222-223`; `RESUMEN_DEFINITIVO_PARA_ARTICULO.md:86-98` |
| **V9** | Las limitaciones L2 (LLM de pago no autorizado) y L10 (Chrome de marca vs CfT) están declaradas con impacto | **L2** (`LIMITACIONES_RESTANTES.md:37-54`): evaluación con LLM de pago real no ejecutada por falta de autorización; "cualquier cifra de mejora atribuible al LLM sería especulativa y no se reporta". **L10** (líneas 168-189): Chrome de marca 155 rechaza `--load-extension` (log literal), la batería corrió en CfT 156, impacto declarado (no se verificó `.crx` ni directivas de empresa). La cadena de rechazo coincide exactamente con el código fuente de Chromium (gated por `GOOGLE_CHROME_BRANDING`) | **APTO (obs. MENOR-4)** | `LIMITACIONES_RESTANTES.md:37-54,168-189`; `artifacts/e2e_chrome/branded_chrome_load_extension.log` |
| **V10** | El artículo Word no fue alterado y el árbol está limpio | `git diff ceb0c9e..HEAD --stat -- "*Article*.docx"` **vacío**; `git status --porcelain` vacío al cierre (tras restaurar la prueba R-01) | **APTO** | git (porcelain + diff vs base) |
| **T-01** | 174 pruebas, 0 fallos | `python -m pytest tests/ -q` → 174 passed, exit 0; JUnit: `tests="174" failures="0" errors="0" skipped="0"` | **APTO** | `%TEMP%\phishpe_audit_junit.xml` |
| **R-01** | `phase2h_build_deliverables.py` es determinista | Re-ejecución: COMPARACION 20 filas, MATRIZ 8 defectos, VALIDACIÓN 12/12, exit 0. `git diff`: **solo** `generated_utc` cambió (1 línea); CSV byte-idénticos; árbol restaurado | **APTO CON OBS. (MENOR-3)** | `git diff` capturado en el registro de auditoría |

---

## 3. Hallazgos

### CRÍTICO
**Ninguno.** No se detectó evidencia de resultados fabricados, de solape entre
cohortes, ni de alteración de los pesos congelados (recomputación interna
N = 691 consistente: Δ = 0.0000 para M0–M3).

### MAYOR

**MAYOR-1 — El manifiesto de congelamiento ya no verifica: hash divergente de un script congelado.**
- `freeze_manifest.json → experiment_scripts_sha256["scripts/phase2g_verify_manual_audit_regressions.py"]`
  = `e1d5d828f02fd1550337085b2e334308687790a8fb0b35e3655011e698e4c2cd`;
  en disco, en git (HEAD) y dentro de `evidencia_phishpe_definitiva.zip` =
  `c6f1c95f651c8368dd95cb90d7f07b2eced418713e01cc300ef24f51beac41e5`.
- El archivo en disco tiene mtime 04:23:49, **posterior** al freeze #3 (04:12:59);
  `phase2g_run2.log` (04:25:28) es posterior y produjo `manual_audit_regressions.json`.
- Consecuencia verificada en código: `phase2c_evaluate_cohort2.py:100-105`
  compara `experiment_scripts_sha256` contra disco y `:877-880` aborta con
  `ABORT: el freeze no coincide con el código actual` → **una re-ejecución
  hoy fallaría**. Las afirmaciones históricas `mismatches=[]` solo fueron
  válidas en el momento de ejecutarse.
- **Corrección sugerida:** re-congelar (phase2a) con el hash vigente o restaurar
  la versión congelada del script, y regenerar la evidencia afectada.

**MAYOR-2 — `07_ANALISIS_ESTADISTICO.md` contradice su propio CSV canónico en 5 de 14 filas.**
- Filas afectadas (MD vs `07_all_hypothesis_tests_table.csv`):
  - **H3** (`07:89` vs CSV línea 4): F1_B 0.9248 vs 0.918768; Δ +0.0590 vs +0.053014; n01 25 vs 23; p 2.74e-5 vs 8.798e-05; Holm 5.49e-5 vs 8.798e-05.
  - **E3** (`07:100`): Δ −0.0067 vs −0.012739; 4/6 vs 2/6; p 0.7539 vs 0.2890625.
  - **E4** (`07:101`): F1_A 0.9248 vs 0.918768; Δ +0.0139 vs +0.019899; 10/6 vs 12/6; p 0.4545 vs 0.23788452.
  - **E6** (`07:103`): 16/8 vs 17/9; p 0.1516 vs 0.16863754; Holm 0.9096 vs 1.0.
  - **E7** (`07:104`): F1 0.9248/0.9178 vs 0.918768/0.902299; 6/10 vs 3/8; p 0.4545 vs 0.2265625.
- Contradicción **interna adicional**: la narrativa `07:156` sí es coherente con
  el CSV (Holm ≤ 8.80e-05 incluye 8.798e-05), mientras que la tabla de la línea 89
  declara 5.49e-05.
- Causa raíz verificada: `artifacts/m4-real/metrics.json` no contiene
  `selected_threshold` → `threshold_of()` en `fase2_07_analisis_estadistico.py`
  cae a 0.5 (F1 M4 = 0.918768 = CSV), mientras el MD usa el F1 por-etapas con
  `predicted_label` (0.924791 ≈ 0.9248), que además reproduce discordancias 25/3.
- Agravante: `phase2e_verify_historical_stats.py` solo aplica 2 comprobaciones
  textuales; su veredicto "14/14 PASS" **no cubre** la consistencia tabla-MD vs CSV.
- Impacto: **ninguna conclusión se invierte** (H3 sigue siendo significativo tras
  Holm; los exploratorios no significativos en ambas versiones), pero un entregable
  corregido no puede contradecir sus datos canónicos. Las 9 filas restantes
  (incluida la nota de corrección E1/E2) verifican exactas.

### MENOR

**MENOR-1 — `phase2b_acquire_cohort2.py` no verifica programáticamente el freeze.**
No hay comprobación de `freeze_manifest.json` en el código (solo nota en el
docstring, línea 521); el orden "congelar → construir cohorte" se sostiene por
convención y timestamps, no por una guarda como la de `phase2c`.

**MENOR-2 — Bloque `freeze` nulo en `VALIDACION_FINAL_AUTOMATICA.json`.**
`manifest_sha256`, `git_commit` y `dirty` = `null` (fallback en
`phase2h_build_deliverables.py:417`), de modo que el certificado de 12/12 PASS
no registra el hash del congelamiento que certifica.

**MENOR-3 — `phase2h` no es bit-determinista.**
La re-ejecución solo cambia `generated_utc` (1 línea); los CSV son
byte-idénticos. Menor, pero documentado: dos ejecuciones no producen el mismo JSON.

**MENOR-4 — Texto corrupto en `LIMITACIONES_RESTANTES.md:184`.**
La frase L10 contiene caracteres CJK ajenos ("no se**验证ó** el empaquetado
`.crx`"), defecto de codificación en un entregable publicado.

*Nota V9:* la atribución "desde la versión 137" del veto a `--load-extension`
no es verificable con evidencia local; la cadena literal del rechazo sí está en
`branded_chrome_load_extension.log` y coincide con el código fuente de Chromium
(bloque `#if BUILDFLAG(GOOGLE_CHROME_BRANDING)`).

---

## 4. VEREDICTO

# APTO CON CONDICIONES

**Fundamento.** El núcleo científico resiste la auditoría adversarial: la cohorte
N = 1,200 es independiente y congelada correctamente (V2), las 14 pruebas
estadísticas son exactamente reproducibles desde el CSV canónico (V3), las
abstenciones y la mortalidad de URLs se tratan honestamente (V4), toda la
evidencia de BUG-01…08 tiene hash real verificado (V5), las 174 pruebas pasan
(T-01), la batería E2E corre en Chrome real con cifras recomputables al detalle
(V7), el coste del BUG-07 y las limitaciones L2/L10 se declaran sin adornos
(V8/V9) y el artículo no fue alterado (V10). No hay hallazgos críticos.

**Condiciones (deben resolverse antes de citar los entregables afectados):**

1. **MAYOR-1:** resincronizar el hash congelado de
   `scripts/phase2g_verify_manual_audit_regressions.py` (re-freeze o restauración)
   para que `verify_freeze()` vuelva a pasar, o documentar la divergencia en
   `FREEZE_HISTORY.md`.
2. **MAYOR-2:** regenerar las tablas H3/E3/E4/E6/E7 de
   `07_ANALISIS_ESTADISTICO.md` desde `07_all_hypothesis_tests_table.csv`
   (o corregir la definición de F1 de M4 en el script) y ampliar la comprobación
   textual de `phase2e` a consistencia tabla-vs-CSV.

**Recomendaciones (no bloqueantes):** MENOR-1 (guarda de freeze en phase2b),
MENOR-2 (bloque `freeze` rellenable en phase2h), MENOR-3 (timestamps
deterministas) y MENOR-4 (texto corrupto de L10).

---

*Reproducibilidad de esta auditoría:* scripts en
`C:\Users\User\AppData\Local\Temp\opencode\phishpe_audit\`
(`audit_freeze.py`, `audit_cohort2.py`, `audit_stats.py`, `audit_md_vs_csv.py`,
`audit_validacion.py`, `audit_e2e2.py`, `audit_e2e3.py`,
`audit_phase2g_versions.py`), ejecutados sobre el commit `96944d4` sin escribir
en el repositorio.
