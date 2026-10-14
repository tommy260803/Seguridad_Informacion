# INFORME DE REPRODUCIBILIDAD — Fase de corrección (2026-10-14)

Este documento resuelve, uno por uno, los siete puntos de reproducibilidad
planteados por la auditoría independiente. Cada resolución es verificable con
un comando y un artefacto concreto. **Ninguna corrección se apoyó en memoria ni
en cifras no recomputables**: para cada discrepancia se recalculó desde los
archivos congelados y se adjuntó la evidencia.

---

## R1. Fechas de ejecución «2026-04-12» vs. evidencia de octubre de 2026

**Observación.** `02_VALIDACION_EXTERNA.md`, `03_EXTENSION_REAL.md` y
`05_CASCADA_ABLACIONES.md` declaraban «Fecha de ejecución: 2026-04-12», pero
los artefactos y el historial Git apuntan a septiembre–octubre de 2026.

**Resolución.** La fecha declarada era un **error tipográfico**; la ejecución
real es de **2026-10-12 UTC**. Pruebas:

| Fuente | Valor observado |
|---|---|
| Commits que generaron los artefactos | `9880ca2`, `d1aa45e` (2026-09-29); `496560a`, `ceb0c9e` (2026-10-06) |
| `captured_at` de los manifiestos de artefactos (`artifacts/corrected_audit/*.json`) | `2026-10-12T00:12:56Z` y posteriores |
| Fecha de modificación de los CSV de predicciones externas | 2026-10-12 |

Los tres documentos han sido corregidos a `2026-10-12` con una nota inline que
deja constancia de la corrección. **Verificación:**

```powershell
Select-String -Path 02_VALIDACION_EXTERNA.md,03_EXTENSION_REAL.md,05_CASCADA_ABLACIONES.md `
  -Pattern "Fecha de ejecuci" | ForEach-Object { "$($_.Filename): $($_.Line.Trim())" }
```

---

## R2. «105,541 dominios únicos» frente a la fuente real

**Observación.** `RESUMEN_DEFINITIVO_PARA_ARTICULO.md` afirmaba que el corpus
de entrenamiento/validación tenía «105,541 dominios únicos». La auditoría no
pudo reconstruir esa cifra.

**Resolución.** La cifra es **incorrecta y queda retirada**. Recomputada desde
`data/processed/0.1.0/samples.csv` (SHA-256
`947350f084c8d1ee842948ee2cf7607df45bb08e3c3a3f66958e25fc3863b89f`):

| Magnitud | Valor recomputado |
|---|---:|
| Filas (URLs) | 176,201 |
| URLs canónicas únicas | 176,201 |
| **Hosts únicos** | **141,247** |
| **Dominios registrados únicos** (PSL) | **130,047** |
| Dominios registrados con al menos una URL phishing | 30,567 |
| Dominios registrados con al menos una URL legítima | 99,994 |
| Dominios registrados presentes en ambas clases | 514 |

**Verificación** (script cerrado, ~60 s):

```powershell
python -c "import csv;from pathlib import Path;p=Path('data/processed/0.1.0/samples.csv');u=set();h=set();r=set();n=0
for row in csv.DictReader(p.open(encoding='utf-8-sig',newline='')):
    n+=1;u.add(row['canonical_url']);h.add(row['host'].lower());r.add(row['registered_domain'].lower())
print(n,len(u),len(h),len(r))"
```

El resumen definitivo usa ahora 130,047 (con su método de cálculo) y advierte
explícitamente de la retirada de la cifra previa. Toda cifra del resumen es
ahora rastreable hasta un artefacto con SHA-256.

---

## R3. Discrepancias entre el texto del informe 07 y su propio CSV de pruebas pareadas

**Observación.** `07_ANALISIS_ESTADISTICO.md` (+0.0127 F1, 9 vs 4, p = 0.2668
en `M2 vs M1`; −0.0007 en `M3 vs M2`) contradecía su CSV publicado
(`07_all_hypothesis_tests_table.csv`).

**Resolución.** Se **recomputaron las 14 filas del CSV desde cero**, a partir de
los `predictions.csv` congelados, con un script independiente
(`scripts/phase2e_verify_historical_stats.py`, que re-implementa el pareo por
`sample_id`, el McNemar exacto por dos colas y el ajuste de Holm–Bonferroni):

- **14/14 filas reproducen exactamente** (ΔF1, pares discordantes, p exacta,
  p Holm): `dictamen: PASS`.
- Evidencia: `artifacts/corrections_phase2/eval/historical_stats_reconciliation.json`.

Por tanto **el CSV era correcto y el texto del informe estaba mal**. Se corrigió
el texto (filas `E1`/`E2` y el párrafo de conclusiones) para coincidir con la
fuente reproducible, y se añadió una **nota de corrección** al inicio del
informe con la tabla de cifras erróneas → corregidas. **Ninguna conclusión
cambia**: `E1` sigue siendo no significativo (más inconcluso aún) y `E2`
sigue siendo un resultado nulo verificado. Las hipótesis confirmatorias
`H1`–`H6` no se veían afectadas.

**Verificación:**

```powershell
python scripts\phase2e_verify_historical_stats.py
```

---

## R4. Ausencia de archivos de candidatos externos excluidos y de los scripts de la cohorte

**Observación.** No se publicaron los descartes de la construcción de la cohorte
externa ni los scripts que la generaron.

**Resolución.** En la fase de corrección se publican, para la nueva cohorte de
confirmación (N = 1,200):

| Artefacto | Contenido |
|---|---|
| `artifacts/corrections_phase2/cohort2/cohort2_candidates_all.csv` | Todos los candidatos descargados de las fuentes (PhishTank, URLhaus, OpenPhish, Tranco, Majestic) con su estado de aceptación |
| `artifacts/corrections_phase2/cohort2/cohort2_excluded.csv` | Candidatos excluidos con **motivo** por fila (duplicado, solape con el corpus interno, sin host válido, etc.) |
| `artifacts/corrections_phase2/cohort2/cohort2_dataset.csv` | Cohorte final congelada (con etiquetas congeladas por separado) |
| `scripts/phase2b_acquire_cohort2.py` | Script íntegro de construcción (semilla 42, determinista) |
| `scripts/phase2a_freeze.py` | Script de congelación de código/modelos/umbrales |

**Verificación:** el SHA-256 del `cohort2_dataset.csv` está registrado en el
manifiesto de congelación y se re-verifica (y aborta) en cada evaluación.

---

## R5. Dependencias y recursos externos no documentados

**Observación.** Faltaba el detalle de versiones exactas y de los recursos
externos (PSL, modelos, listas de marcas).

**Resolución.**

| Recurso | Especificación y procedencia |
|---|---|
| Dependencias Python | `requirements-lock.txt` (335 versiones congeladas) + `pyproject.toml` |
| Public Suffix List | Descargada y cacheada por `phishguard_infra.registro`; se indexa Tranco Top-1M desde `data/raw/20260919T192154.381983Z/tranco.csv.zip` |
| Modelos M0–M3 (9 artefactos) | Ruta, SHA-256, bytes, nº de características, umbral seleccionado y perfil de características en `artifacts/corrections_phase2/freeze_manifest.json → models` (tabla resumen en la §7 de este documento) |
| Marcas de homógrafos | `POPULAR_TARGET_BRANDS` en `src/phishguard_ml/homoglyphs.py` (10 marcas, código incluido en el repo) |
| Chrome del sistema | `C:\Program Files\Google\Chrome\Application\chrome.exe` (versión registrada en los artefactos E2E) |
| Playwright | `1.64.0` (registrada en el lock) |

---

## R6. Pruebas E2E en Chrome real vs. simulación ASGI

**Observación.** La validación de la extensión se apoyaba en un cliente ASGI de
pruebas, no en Chrome real.

**Resolución.** Se ejecutó una **batería E2E con Chrome real** (navegador
sistema, backend real en `:8080`, extensión empaquetada cargada con perfil
efímero, red HTTP real, sin mocks ni ASGI), instrumentando el *badge* de la
extensión mediante DevTools/CDP: resultados en `E2E_CHROME_RESULTS.md` y
artefactos crudos en `artifacts/e2e_chrome/`. Los tiempos E2E citados son
tiempos **reales de pared** medidos por escena (no sumas de medianas). Los
escenarios no ejecutables quedan marcados `NOT_RUN` con su motivo, nunca
reemplazados por simulación.

---

## R7. Identificación de modelos y umbrales

**Observación.** No existía una tabla que identificara cada modelo con su hash,
umbral y características.

**Resolución.** Generada automáticamente desde el manifiesto de congelación
(`artifacts/corrections_phase2/freeze_manifest.json → models`):

| Modelo | SHA-256 (12 primeros) | Nº feats | Umbral | Perfil/candidato |
|---|---|---:|---:|---|
| `artifacts/url-baseline-0.2.0/model.joblib` (M0 baseline) | `6621b72b6bbf` | 11 | 0.4339 | `authority_only` |
| `artifacts/m0-real/model.joblib` (M0) | `249e6e387e74` | 11 | 0.3827 | `histgb-63-sigmoid` |
| `artifacts/m0-ite-real/model.joblib` | `dbd23b800360` | 11 | 0.4127 | `histgb-31-sigmoid` |
| `artifacts/m1-real/model.joblib` (M1) | `c139ebe5dc04` | 36 | 0.5250 | `histgb-31-sigmoid` |
| `artifacts/m1-ite-real/model.joblib` | `783aecb9c115` | 36 | 0.5646 | `histgb-31-sigmoid` |
| `artifacts/m2-real/model.joblib` (M2) | `9da6de033d70` | 62 | 0.3950 | `histgb-31-sigmoid` |
| `artifacts/m2-ite-real/model.joblib` | `95cd392bb3ae` | 62 | 0.5966 | `histgb-31-sigmoid` |
| `artifacts/m3-real/model.joblib` (M3) | `c17877f5af4d` | 75 | 0.4343 | `histgb-63-sigmoid` |
| `artifacts/corrected_audit/m3-authentic-cdp/model.joblib` | `39198a362da1` | 75 | 0.5000 | auténtico CDP |

Umbrales y política globales congelados (misma fuente):

| Parámetro | Valor congelado |
|---|---|
| `uncertainty_threshold` (parada temprana) | 0.15 |
| `abstention_threshold` (abstención final, **parámetro separado**) | 0.20 |
| `minimum_confidence` | 0.80 |
| Presupuesto / costes de cascada | 3.0 / infra 1.0, contenido 1.0, visual 1.0 |
| Timeout de cliente | 8000 ms |
| Mezcla LLM | 0.7 · p_cascada + 0.3 · p_LLM |

---

## R8. Barrido de secretos y determinismo de marcas de tiempo

**Barrido de secretos a árbol completo (condición C‑4).** Antes de cada commit
de esta fase se ejecuta:

```powershell
python scripts\_secret_scan_before_commit.py   # exit 0 obligatorio
```

Recorre `git ls-files` **más** los no rastreados no ignorados (~316 ficheros),
con 9 patrones de credenciales. Resultado actual: **0 secretos sin documentar**.
Dos hallazgos quedan clasificados y **nunca silenciados**:

- `extension.pem` → `PREEXISTING_DOCUMENTED` (clave de firmado de la extensión
  preexistente al histórico; ver limitación **L11** con el plan de rotación).
- La clave pública de Firebase `AIzaSy…` dentro de la URL de un dataset en
  `01_AUDITORIA_BASELINE.md` → `ALLOWLIST_BY_PATH` (parámetro OAuth público
  documentado como hallazgo, no una credencial del proyecto).

**Determinismo de marcas de tiempo (condición MENOR‑3).** Los generadores
`phase2h_build_deliverables.py` y `phase2k_summarize_e2e.py` aceptan la variable
estándar `SOURCE_DATE_EPOCH`: si se define, la marca `generated_utc` /
«Generado:» se fija a ese instante y la regeneración queda **byte-idéntica**;
si no, se usa el UTC actual (único campo no determinista de esos artefactos,
acotado y documentado).

---

## Orden del protocolo y congelaciones

El orden respetado fue: **congelar** (código, modelos, umbrales, snapshots del
commit base) → **construir la cohorte2 consultando etiquetas** → **evaluar**.
Hay tres congelaciones documentadas en
`artifacts/corrections_phase2/FREEZE_HISTORY.md`, con el motivo y el hash de
cada una. Ninguna re-congelación alteró modelos ni umbrales: la #2 corrigió un
defecto del **script de medición**, la #3 el **BUG-08** (falsos positivos de
Levenshtein) detectado al auditar los propios resultados de la #2, y la #4/#5
las **correcciones de las dos auditorías finales** (C‑2 homógrafos, C‑3 TLS,
B‑07 comentario), con `models`, `thresholds_and_normalization` y
`baseline_original_config_A_B` byte-idénticos entre #3 y #5 (ver
`eval/offline_revalidation.json → freeze_invariants_vs_prev`).

**Verificación de la congelación vigente (offline, sin red):**

```powershell
python scripts\phase2n_revalidate_offline.py   # verify_freeze() + reproducción byte a byte
# → artifacts/corrections_phase2/eval/offline_revalidation.json → "dictamen": "PASS" (11/11)
```

> **No** re-ejecute `phase2c_evaluate_cohort2.py` para verificar el freeze: su
> bloque B/C sondea 600 URLs en vivo y regeneraría `probe_*` con deriva de red.
> El registro histórico de esa corrida (bajo freeze #3) se conserva intacto en
> `eval/`, y `phase2n` prueba que los bloques offline (A, D, E) reproducen
> exactamente esos artefactos bajo el freeze #5 vigente.

---

## Nota sobre la cohorte externa histórica «n1200»

Los archivos `external_predictions_n1200.csv` y
`external_validation_dataset_n1200.csv` del ciclo anterior contienen en realidad
**1,054 filas** (verificado contándolas). El nombre del archivo es engañoso pero
el contenido es el que se usó y se reportó como N = 1,054 en los informes. En
esta fase se publica una **cohorte nueva, independiente y de tamaño real
verificado (N = 1,200)**, que no reutiliza esas 1,054 URLs como única prueba
confirmatoria.
