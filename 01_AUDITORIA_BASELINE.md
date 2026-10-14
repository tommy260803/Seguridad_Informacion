# FASE I: Auditoría de Reproducibilidad y Congelación del Baseline — Proyecto PhishPe (PhishGuard)

**Fecha de ejecución:** 12–13 de octubre de 2026 (`2026-10-13T02:13:55Z`)  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit Git base congelado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Script verificador reproducible:** [fase2_01_auditoria_baseline.py](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_01_auditoria_baseline.py)  
**Artefacto JSON de salida:** [01_auditoria_baseline_results.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase1_auditoria/01_auditoria_baseline_results.json)

---

## 1. Entorno Experimental y Versiones Verificadas

| Componente | Valor Verificado en Ejecución | Estado |
| :--- | :--- | :---: |
| **Procesador (CPU)** | `13th Gen Intel(R) Core(TM) i5-13600K` (`14` núcleos físicos / `20` hilos lógicos, `AMD64`) | `PASS` |
| **Memoria RAM Física** | `15.78 GB` | `PASS` |
| **Sistema Operativo** | `Windows 11` (`10.0.26200`) | `PASS` |
| **Intérprete Python** | `CPython 3.12.10` | `PASS` |
| **Librerías Científicas Clave** | `scikit-learn 1.7.2`, `numpy 2.4.6`, `scipy 1.15.3`, `joblib 1.5.3`, `pandas 3.0.5`, `httpx 0.28.1`, `Pillow 12.3.0`, `matplotlib 3.10.8`, `fastapi 0.141.1`, `pydantic 2.13.5` | `PASS` |
| **Suite de Pruebas (`pytest -q`)** | **`127 passed`** (`0 failed`, tiempo `~38 s`) | `PASS` |
| **Public Suffix List (PSL)** | [public_suffix_list.dat](file:///d:/Proyects/Seguridad_Informacion/data/raw/public_suffix_list.dat) (`334,229` bytes, `sha256: 330c1c710ba29ecb...`) | `PASS` |
| **Fuentes Crudas Originales** | `data/raw/20260919T192154.381983Z/tranco.csv.zip` (`9,726,388` B) y `phishtank.csv.bz2` (`2,268,769` B) | `PASS` |

---

## 2. Integridad del Corpus Maestro (`samples.csv`) y Sesgo de Procedencia

Se auditó exhaustivamente el archivo maestro [samples.csv](file:///d:/Proyects/Seguridad_Informacion/data/processed/0.1.0/samples.csv) (`62,268,029` bytes):

- **Total de registros:** `176,201` filas de datos (100 % con `sample_id` único).
- **Distribución por clase:**
  - `legitimate`: **`99,994`** (`56.75 %`) — 100 % provenientes de `tranco` (`url_origin = constructed_from_domain`).
  - `phishing`: **`76,207`** (`43.25 %`) — 100 % provenientes de `phishtank` (`url_origin = reported_url`).
- **Campos críticos faltantes (`sample_id`, `canonical_url`, `label`):** `0`.
- **URLs canónicas duplicadas:** `0`.
- **Verificación de `registered_domain` con Public Suffix List:** `0` discrepancias en las 2,000 filas auditadas directamente.
- **Hallazgo metodológico crítico (Confounding fuente–clase en `0.1.0`):** En el dataset `0.1.0`, la fuente de origen está perfectamente acoplada con la etiqueta (`tranco -> legitimate`, `phishtank -> phishing`), y las URLs de Tranco fueron construidas a partir del nombre de dominio raíz (`https://<domain>/`). Esto implica que un clasificador podría explotar artefactos de estructura de ruta o popularidad de dominio si no se restringe al perfil `authority_only` (11 variables de host) y si no se valida con un conjunto externo multi-fuente (implementado en la Fase II).

---

## 3. Auditoría de Solapamiento en Particiones (Dominio Registrado PSL, URLs y Redirecciones HTTP)

Se verificaron las cuatro particiones oficiales en `data/processed/0.1.0/splits/` cruzando:
1. Identificador `sample_id`.
2. Host exacto (`host`).
3. URL canónica (`canonical_url`).
4. Dominio registrado inicial (`registered_domain` extraído mediante Public Suffix List).
5. **Nuevo control de auditoría:** Dominio registrado de destino tras redirecciones HTTP (`final_url` en `infrastructure-results-real.jsonl`, donde `564` de las `10,000` URLs sondeadas redirigen a un dominio registrado distinto al inicial, p. ej. acortadores `qrco.de`, `bit.ly` o servicios de hosting).

| Partición (`splits/*.csv`) | Total Muestras | `train` / `val` / `test` | Solap. `sample_id` (`tr-val` / `tr-te` / `val-te`) | Solap. `canonical_url` (`tr-val` / `tr-te` / `val-te`) | Solap. `registered_domain` Inicial PSL (`tr-val` / `tr-te` / `val-te`) | Solap. Dominio Final Post-Redirección en 10k (`tr-val` / `tr-te` / `val-te`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`conventional.csv`** | 176,201 | `123,341 / 26,430 / 26,430` | `0 / 0 / 0` | `0 / 0 / 0` | `1,653 / 1,681 / 625` | `71 / 60 / 40` |
| **`host_unseen.csv`** | 176,201 | `123,341 / 26,430 / 26,430` | **`0 / 0 / 0`** | **`0 / 0 / 0`** | **`0 / 0 / 0`** | `13 / 11 / 6` |
| **`temporal.csv`** | 176,201 | `141,129 / 17,447 / 17,625` | `0 / 0 / 0` | `0 / 0 / 0` | `195 / 191 / 111` | `24 / 23 / 12` |
| **`temporal_host_unseen.csv`** | 173,633 | `141,129 / 16,020 / 16,484` | **`0 / 0 / 0`** | **`0 / 0 / 0`** | **`0 / 0 / 0`** | `11 / 7 / 3` |

> [!IMPORTANT]
> **Hallazgo de auditoría sobre redirecciones HTTP:** Mientras que `host_unseen.csv` y `temporal_host_unseen.csv` garantizan **0 solapamiento** de dominios registrados iniciales (`0 / 0 / 0`), el seguimiento de redirecciones HTTP en la cohorte de 10,000 URLs revela que `11` dominios registrados de destino final (`final_url`) aparecen tanto en `train` como en `test` de `host_unseen` (debido a múltiples URLs distintas en acortadores o proveedores cloud que redirigen a una misma plataforma destino). Las características léxicas de `M0` se extraen exclusivamente de la URL inicial (sin seguir redirecciones), mientras que `M1` codifica `redirect_registered_domain_change_count` como variable numérica agregada sin memorizar el string del dominio destino.

---

## 4. Hashes SHA-256 de Modelos Congelados y Artefactos Críticos

Todos los modelos quedan congelados con sus hashes SHA-256 verificados antes de iniciar los experimentos de las Fases II–VII:

| Artefacto / Archivo Crítico | Tamaño (Bytes) | Hash SHA-256 Completo | Tipo / Características |
| :--- | :---: | :--- | :--- |
| `data/processed/0.1.0/samples.csv` | `62,268,029` | `947350f084c8d1ee842948ee2cf7607df45bb08e3c3a3f66958e25fc3863b89f` | Corpus maestro (`N=176,201`) |
| `data/processed/0.1.0/splits/host_unseen.csv` | `12,616,011` | `8adc72928bf6d694d0b70fb3fa4071304bd8fb275208cb2630b710c5420a6fe1` | Partición disjunta por dominio |
| `data/processed/0.1.0/splits/temporal.csv` | `12,579,901` | `9449ee4e0c31cdba9b6f338d3c497f74308b90ae62df299fb087d63239e0258a` | Partición temporal (`test=17,625`) |
| `data/processed/0.1.0/splits/temporal_host_unseen.csv` | `12,391,579` | `a04b282fee73b9abafccbe5c4207a48d8eeb1d4784cad8e3456539a641d8f7c1` | Partición temporal + host-unseen (`test=16,484`) |
| `artifacts/url-baseline-0.2.0/model.joblib` | `223,340` | `6621b72b6bbf426d1b17c39f475e5fa659602071513db81d430371e015c2087d` | `CalibratedClassifierCV` (11 vars, corpus completo `host_unseen`, $\tau^*=0.433937$) |
| `artifacts/m0-real/model.joblib` | `1,086,080` | `249e6e387e74d842b3312470fe7a8f548f86908c9447e8c54c9b41676c938912` | `CalibratedClassifierCV` (11 vars, cohorte CC `N_train=4,219`, $\tau^*=0.382667$) |
| `artifacts/m1-real/model.joblib` | `562,402` | `c139ebe5dc042d7558a30d2bdd85016b279e4557324a40731f663062597316d9` | `CalibratedClassifierCV` (36 vars, cohorte CC, $\tau^*=0.525014$) |
| `artifacts/m2-real/model.joblib` | `582,033` | `9da6de033d70318397ab2d973f44dedaee42156d51b57a00113fdbc8ec6a8400` | `CalibratedClassifierCV` (62 vars, cohorte CC, $\tau^*=0.394962$) |
| `artifacts/m3-real/model.joblib` | `1,132,973` | `c17877f5af4d4176f7f296b941acd96b1d8c09e2af573efe4e10929c0fc44fe7` | `CalibratedClassifierCV` (75 vars, cohorte CC con proxy DOM, $\tau^*=0.434336$) |
| `artifacts/corrected_audit/m3-authentic-cdp/model.joblib` | `267,137` | `39198a362da18e819bb8a0a79748d35e4694b037f2cf7cf534bf58c167ef0de3` | `CalibratedClassifierCV` (75 vars, 100 % Chrome CDP `N_train=313`, $\tau^*=0.500000$) |
| `artifacts/m0-ite-real/model.joblib` | `549,632` | `dbd23b80036090576d6cccea5150d5831d0c7602e5fde6e5179ab92390335a1d` | `CalibratedClassifierCV` (11 vars, cohorte ITE `N=10,000`, $\tau^*=0.412708$) |
| `artifacts/m1-ite-real/model.joblib` | `564,194` | `783aecb9c115fd67d927ce53e7daf0515caac36f8d76598f83d98af3f3e00258` | `CalibratedClassifierCV` (36 vars, cohorte ITE, $\tau^*=0.564585$) |
| `artifacts/m2-ite-real/model.joblib` | `583,889` | `95cd392bb3aea8dd416af0cd8f4f5ffcb011a42e859a098976cb0873b8696849` | `CalibratedClassifierCV` (62 vars, cohorte ITE, $\tau^*=0.596635$) |
| `artifacts/m3-ite-real/model.joblib` | `599,261` | `deba99644f7ed6d199bf189fc87bfd7f8b28b3ceabd390df76e70a1a16d5065e` | `CalibratedClassifierCV` (75 vars, cohorte ITE, $\tau^*=0.455440$) |
| `artifacts/m0-temporal/model.joblib` | `223,064` | `6787335a2e647ddcb34cff124539fcba84424bbd9f6fb184267a5075393f7aeb` | `CalibratedClassifierCV` (11 vars, `temporal.csv`, $\tau^*=0.274225$) |
| `artifacts/m0-temporal-host-unseen/model.joblib` | `223,065` | `3b23e6256849b41ddb677a8bde8faee3839c933c1252f18af1280b9d331924bf` | `CalibratedClassifierCV` (11 vars, `temporal_host_unseen.csv`, $\tau^*=0.256980$) |

> [!NOTE]
> **Distinción arquitectónica entre los dos modelos `M0` en disco:**
> - `artifacts/url-baseline-0.2.0/model.joblib` fue entrenado sobre la partición `train` del corpus completo `host_unseen` ($N_{\text{train}}=123,341$) y es el modelo cargado por `HybridM0Model` (en `POST /check`) y como primera opción por `UnifiedModelManager` (en `src/phishguard_api/inference.py`).
> - `artifacts/m0-real/model.joblib` fue entrenado exclusivamente sobre la partición `train` de la cohorte multimodal Complete-Case ($N_{\text{train}}=4,219$) para garantizar que las etapas `M0`, `M1`, `M2` y `M3` del experimento de ablación multimodal compartan exactamente el mismo conjunto de entrenamiento. En la Fase II evaluaremos **ambos** modelos `M0` congelados sobre el nuevo dataset externo independiente.

---

## 5. Recálculo Independiente de Métricas y Tabla de Correspondencia

Todas las métricas fueron recalculadas directamente desde los archivos `predictions.csv` cruzando cada `sample_id` con la etiqueta maestra en `samples.csv` (`0` discrepancias de etiquetas en los 15 experimentos):

| Experimento | Artefacto (`predictions.csv`) | $N_{\text{test}}$ | $\tau^*$ | TN | FP | FN | TP | Acc. Recalc. | Prec. Recalc. | Rec. Recalc. | **F1 Recalc.** | **F1 en `metrics.json`** | **F1 en Manuscrito Preliminar (Desactualizado)** | Dif. vs `metrics.json` | Estado |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`M0_CC_host_unseen`** | `artifacts/m0-real/` | 691 | `0.382667` | 484 | 16 | 33 | 158 | `0.929088` | `0.908046` | `0.827225` | **`0.865753`** | `0.865753` | `0.8665` *(preliminar)* | `0.000000` | `PASS` |
| **`M1_CC_host_unseen`** | `artifacts/m1-real/` | 691 | `0.525014` | 497 | 3 | 24 | 167 | `0.960926` | `0.982353` | `0.874346` | **`0.925208`** | `0.925208` | `0.8604` *(preliminar)* | `0.000000` | `PASS` |
| **`M2_CC_host_unseen`** | `artifacts/m2-real/` | 691 | `0.394962` | 496 | 4 | 21 | 170 | `0.963821` | `0.977011` | `0.890052` | **`0.931507`** | `0.931507` | `0.9020` *(preliminar)* | `0.000000` | `PASS` |
| **`M3_CC_host_unseen`** | `artifacts/m3-real/` | 691 | `0.434336` | 496 | 4 | 22 | 169 | `0.962373` | `0.976879` | `0.884817` | **`0.928571`** | `0.928571` | `0.9301` *(preliminar)* | `0.000000` | `PASS` |
| **`M4_fixed_CC_host_unseen`** | `artifacts/m4-fixed-real/` | 691 | `0.434336` | 499 | 1 | 33 | 158 | `0.950796` | `0.993711` | `0.827225` | **`0.902857`** | `0.902857` | — | `0.000000` | `PASS` |
| **`M4_CC_host_unseen`** | `artifacts/m4-real/` | 691 | Por etapa | 498 | 2 | 25 | 166 | `0.960926` | `0.988095` | `0.869110` | **`0.924791`** | `0.924791` | — | `0.000000` | `PASS` |
| **`M5_CC_host_unseen` (Forzado)** | `artifacts/m5-real/` | 691 | Por etapa | 498 | 2 | 25 | 166 | `0.960926` | `0.988095` | `0.869110` | **`0.924791`** | `0.924791` | — | `0.000000` | `PASS` |
| **`M5_CC_host_unseen` (Selectivo)** | `artifacts/m5-real/` (`abstained==0`) | **662** | Por etapa | 492 | 0 | 15 | 155 | `0.977341` | `1.000000` | `0.911765` | **`0.953846`** | `0.953846` | `0.9538` | `0.000000` | `PASS` |
| **`M0_ITE_host_unseen`** | `artifacts/m0-ite-real/` | 1,500 | `0.412708` | 820 | 31 | 129 | 520 | `0.893333` | `0.943739` | `0.801233` | **`0.866667`** | `0.866667` | — | `0.000000` | `PASS` |
| **`M1_ITE_host_unseen`** | `artifacts/m1-ite-real/` | 1,500 | `0.564585` | 827 | 24 | 113 | 536 | `0.908667` | `0.957143` | `0.825886` | **`0.886683`** | `0.886683` | — | `0.000000` | `PASS` |
| **`M2_ITE_host_unseen`** | `artifacts/m2-ite-real/` | 1,500 | `0.596635` | 831 | 20 | 110 | 539 | `0.913333` | `0.964222` | `0.830508` | **`0.892384`** | `0.892384` | — | `0.000000` | `PASS` |
| **`M3_ITE_host_unseen`** | `artifacts/m3-ite-real/` | 1,500 | `0.455440` | 817 | 34 | 90 | 559 | `0.917333` | `0.942664` | `0.861325` | **`0.900161`** | `0.900161` | — | `0.000000` | `PASS` |
| **`M0_full_host_unseen`** | `artifacts/url-baseline-0.2.0/` | 26,430 | `0.433937` | 14,423 | 576 | 2,225 | 9,206 | `0.894022` | `0.941116` | `0.805354` | **`0.867958`** | `0.867958` | `0.8680` | `0.000000` | `PASS` |
| **`M0_full_temporal`** | `artifacts/m0-temporal/` | 17,625 | `0.274225` | 9,550 | 454 | 1,884 | 5,737 | `0.867348` | `0.926668` | `0.752788` | **`0.830727`** | `0.830727` | `0.8312` *(17,725 ant.)* | `0.000000` | `PASS` |
| **`M0_full_temporal_host_unseen`** | `artifacts/m0-temporal-host-unseen/` | 16,484 | `0.256980` | 9,507 | 452 | 1,773 | 4,752 | `0.865021` | `0.913144` | `0.728276` | **`0.810299`** | `0.810299` | — | `0.000000` | `PASS` |
| **`M3_authentic_cdp`** | `artifacts/corrected_audit/m3-authentic-cdp/` | 83 | `0.500000` | 51 | 4 | 2 | 26 | `0.927711` | `0.866667` | `0.928571` | **`0.896552`** | `0.896552` | — | `0.000000` | `PASS` |

---

## 6. Auditoría de Secretos y Credenciales

1. **Escaneo de expresiones regulares (`gsk_`, `AIza`, `sk-`, `PRIVATE KEY`):**
   - Ningún archivo de código fuente (`src/`, `scripts/`, `configs/`) contiene credenciales embebidas.
   - La única coincidencia del patrón `AIza` en `artifacts/corrected_audit/m3_visual_audit_and_authentic_evaluation.json` corresponde a una URL pública del propio dataset (`https://auth.wokwi.com/__/auth/handler?apiKey=AIzaSyDeSOFTk-xhmymi82SYFffgcxVOqRKh-Os...`), es decir, un parámetro OAuth público de Firebase dentro de una URL analizada, no una clave del proyecto.
2. **Archivos sensibles locales excluidos de distribución:**
   - `.env` (126 bytes en raíz) y `extension.pem` (1,704 bytes en raíz) existen localmente en el entorno de trabajo y están **estrictamente excluidos** del paquete reproducible `.zip`.

---

## 7. Pre-Registro del Protocolo Científico y Criterios Estadísticos (Fases II a VII)

De acuerdo con la Sección 3 del encargo, se establecen **antes de ejecutar los nuevos experimentos** las hipótesis confirmatorias, comparaciones principales y criterios estadísticos:

1. **Hipótesis Confirmatorias Pre-registradas:**
   - **H1 (Generalización Externa):** Los modelos congelados de PhishPe mantienen un poder discriminativo ($\text{ROC-AUC} \ge 0.80$) sobre un conjunto externo multi-fuente de dominios registrados nunca vistos ($\text{solapamiento PSL} = 0$), pero sufren una caída cuantificable respecto al test interno debido al cambio de distribución de fuentes (*dataset shift*, particularmente cuando las URLs legítimas incluyen rutas profundas y dominios fuera del top de Tranco).
   - **H2 (Aporte Multimodal):** La incorporación de características de infraestructura DNS/TLS (`M1`) y de contenido HTML/DOM (`M2`) mejora significativamente la clasificación respecto al modelo léxico puro (`M0`) al nivel $\alpha = 0.05$ con corrección de Holm-Bonferroni.
   - **H3 (Eficiencia vs. Riesgo de la Cascada):** La cascada adaptativa reduce el número medio de modalidades consultadas y la latencia mediana en al menos un $40\%$ respecto a la evaluación exhaustiva `M2`/`M3`, a costa de falsos negativos tempranos en `M0` que deben cuantificarse explícitamente.
   - **H4 (Efecto del Escudo de Reputación Tranco en la Extensión):** El rendimiento del endpoint de producción `POST /check` (`HybridM0Model`) depende significativamente de la pertenencia del dominio a Tranco Top-1M; al evaluar dominios benignos fuera de Tranco o con rutas complejas, su tasa de falsos positivos aumenta respecto al `0.00%` observado en el test interno.
2. **Criterios Estadísticos Obligatorios:**
   - Semilla aleatoria global fija: `SEED = 42` (y `20260916` para reproducir particiones de calibración históricas).
   - Intervalos de confianza al $95\%$ mediante **bootstrap pareado estratificado/agrupado por dominio registrado** ($B = 2,000$ réplicas).
   - Prueba exacta binomial de **McNemar** para comparaciones binarias pareadas sobre idéntico denominador, con tamaño de efecto (**Odds Ratio discordante** y **$g$ de Cohen**).
   - Ajuste por comparaciones múltiples mediante el procedimiento escalonado de **Holm-Bonferroni** ($\alpha = 0.05$).
   - Separación explícita entre análisis **Confirmatorios** (definidos en este protocolo) y **Exploratorios** (cualquier desglose post-hoc por fuente, TLD o subgrupo).
