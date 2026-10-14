# FASE II: VALIDACIÓN EXTERNA INDEPENDIENTE

**Fecha de ejecución:** 2026-10-12 *(corregido 2026-10-14: la fecha declarada 2026-04-12 era un error tipográfico; la ejecución real es de 2026-10-12 UTC, verificado por los captured_at de los manifiestos de artefactos y por los tiempos de los archivos)*  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Scripts de generación y evaluación:**
- [fase2_02_fetch_external_feeds.py](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_02_fetch_external_feeds.py)
- [fase2_02_build_and_evaluate_external.py](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_02_build_and_evaluate_external.py)
- [fase2_02b_external_forensic_analysis.py](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_02b_external_forensic_analysis.py)

**Artefactos primarios generados:**
- [external_validation_dataset_n1200.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_validation_dataset_n1200.csv) ($N = 1{,}054$ muestras estrictamente disjuntas por dominio registrado respecto a `samples.csv`)
- [external_contaminated_candidates.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_contaminated_candidates.csv) ($2{,}606$ candidatos excluidos del conjunto de generalización estricta por solapamiento de `registered_domain` con `0.1.0`)
- [external_predictions_n1200.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_predictions_n1200.csv)
- [external_multimodal_probe_n240.jsonl](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/external_multimodal_probe_n240.jsonl)
- [02_validacion_externa_results.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/02_validacion_externa_results.json)
- [02b_external_forensic_www_ablation.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/02b_external_forensic_www_ablation.json)

---

## 1. Justificación Estadística del Tamaño de Muestra (*A Priori*)

Antes de recolectar la cohorte externa, se determinó el tamaño muestral requerido mediante precisión esperada de intervalos de confianza de Wald/Wilson al $95\%$ ($z_{0.975} = 1.96$) para proporciones de sensibilidad (*recall*), especificidad y tasa de falsos positivos ($\text{FPR}$), con semiamplitud máxima $e \le 0.05$:

$$n_{\text{clase}} \ge \frac{z_{0.975}^2 \cdot p(1 - p)}{e^2}$$

- Bajo el supuesto más conservador ($p = 0.50$, varianza máxima):
  $$n_{\text{clase}} \ge \frac{1.96^2 \times 0.25}{0.05^2} = 384.16 \implies 385 \text{ muestras por clase}$$
- Bajo $p = 0.85$ (sensibilidad esperada):
  $$n_{\text{clase}} \ge \frac{1.96^2 \times 0.85 \times 0.15}{0.05^2} = 195.92 \implies 196 \text{ muestras por clase}$$

La cohorte externa estrictamente disjunta alcanzada comprende **$N = 1{,}054$ URLs evaluables** (**$600$ de phishing** y **$454$ legítimas**), superando el umbral conservador de $385$ muestras por clase y garantizando una semiamplitud de error muestral $\le \pm 4.0\%$ para phishing y $\le \pm 4.6\%$ para la clase legítima.

---

## 2. Procedencia de los Datos y Control de Contaminación

Para evitar el sesgo de fuente única (*single-source bias* — donde en el dataset histórico `0.1.0` el $100\%$ de la clase legítima provino de Tranco Top-1M y el $100\%$ del phishing provino de PhishTank), se construyó un diseño **multifuente por clase** empleando seis fuentes públicas independientes descargadas el `2026-04-12`:

| Clase | Fuente | URL de origen | Licencia / Condiciones | Candidatos brutos | Solapados con `0.1.0` (`registered_domain`) | Seleccionados disjuntos ($N=1{,}054$) | En Tranco Top-1M |
|---|---|---|---|---:|---:|---:|---:|
| **Phishing (`1`)** | **OpenPhish Community Feed** | `https://openphish.com/feed.txt` | Uso gratuito de investigación / atribución | $300$ | $14$ | **$220$** | $3$ ($1.36\%$) |
| **Phishing (`1`)** | **CERT.PL (CSIRT NASK Polonia)** | `https://hole.cert.pl/domains/v2/domains.txt` | Datos abiertos CSIRT nacional | $126{,}037$ | $91$ | **$190$** | $0$ ($0.00\%$) |
| **Phishing (`1`)** | **Phishing Army Blocklist** | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | CC BY-NC-SA 4.0 | $139{,}318$ | $112$ | **$190$** | $0$ ($0.00\%$) |
| **Legítima (`0`)** | **Majestic Million (Top-2500)** | `https://downloads.majestic.com/majestic_million.csv` | CC BY 3.0 (atribución Majestic) | $2{,}499$ | $2{,}445$ ($97.8\%$) | **$54$** | $26$ ($48.15\%$) |
| **Legítima (`0`)** | **Hipo World Universities** | `https://raw.githubusercontent.com/Hipo/university-domains-list/master/world_universities_and_domains.json` | MIT License | $10{,}268$ | $79$ | **$200$** | $92$ ($46.00\%$) |
| **Legítima (`0`)** | **CISA Official US `.gov` Registry** | `https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv` | Dominio público EE. UU. (CC0 1.0) | $16{,}877$ | $44$ | **$200$** | $32$ ($16.00\%$) |
| **Total** | **6 fuentes independientes** | — | — | **$295{,}299$** | **$2{,}606$** (en submuestra) | **$1{,}054$** | **$153$** |

### Controles de integridad y desduplicación aplicados:
1. **Exclusión estricta por dominio registrado (Public Suffix List):** Se extrajo el `registered_domain` mediante `PublicSuffixList` para las $176{,}201$ filas de `samples.csv` ($105{,}541$ dominios únicos). Cualquier URL candidata cuyo `registered_domain` coincidiera con `train`, `val` o `test` de `0.1.0` fue separada en `external_contaminated_candidates.csv` ($2{,}606$ registros, de los cuales $2{,}445$ provenían de Majestic Million al coincidir el *head* de Majestic con el Top-100k de Tranco). El conjunto principal de evaluación externa ($N = 1{,}054$) tiene **$0.00\%$ de solapamiento de dominios registrados** con `samples.csv`.
2. **Desduplicación interna:** Cada una de las $1{,}054$ muestras corresponde a un `registered_domain` único ($1{,}054$ dominios registrados distintos).
3. **Congelamiento estricto de modelos:** Todos los modelos (`M0_CC`, `M0_full`, `M0_ITE`, `M0_temporal`, `M0_temporal_host_unseen`, `M1`, `M2`, `M4`, `M5` y `HybridM0Model`) fueron evaluados con sus pesos y umbrales originales congelados, sin reentrenamiento ni recalibración.

---

## 3. Resultados a Nivel URL sobre la Cohorte Externa Completa ($N = 1{,}054$)

### 3.1 Comparación de todos los modelos congelados de nivel URL (Confirmatorio)

| Modelo | Artefacto / Configuración | Umbral ($\tau$) | Accuracy | Precision | Recall (TPR) | F1-score [IC 95% Bootstrap] | FPR | FNR | ROC-AUC [IC 95%] | PR-AUC | Brier | ECE |
|---|---|---:|---:|---:|---:|---|---:|---:|---|---:|---:|---:|
| **`M0_CC_host_unseen`** | `artifacts/m0-real/model.joblib` | `0.3827` | `0.4649` | `0.5389` | `0.4383` | `0.4835` `[0.4437, 0.5205]` | `0.4956` | `0.5617` | `0.4648` `[0.4299, 0.5015]` | `0.5356` | `0.4298` | `0.4245` |
| **`M0_full_host_unseen`** | `artifacts/url-baseline-0.2.0/model.joblib` | `0.4339` | `0.4782` | `0.5527` | `0.4367` | `0.4879` `[0.4493, 0.5245]` | `0.4670` | `0.5633` | `0.4859` `[0.4508, 0.5206]` | `0.5594` | `0.4166` | `0.4109` |
| **`M0_ITE_host_unseen`** | `artifacts/m0-ite-real/model.joblib` | `0.4127` | `0.4706` | `0.5449` | `0.4350` | `0.4838` `[0.4455, 0.5209]` | `0.4824` | `0.5650` | `0.4703` `[0.4356, 0.5063]` | `0.5416` | `0.4202` | `0.4124` |
| **`M0_temporal`** | `artifacts/m0-temporal/model.joblib` | `0.2742` | `0.4877` | `0.5595` | `0.4700` | `0.5109` `[0.4727, 0.5474]` | `0.4890` | `0.5300` | `0.4730` `[0.4382, 0.5082]` | `0.5453` | `0.4241` | `0.4170` |
| **`M0_temporal_host_unseen`** | `artifacts/m0-temporal-host-unseen/model.joblib` | `0.2570` | `0.4877` | `0.5595` | `0.4700` | `0.5109` `[0.4735, 0.5471]` | `0.4890` | `0.5300` | `0.4774` `[0.4426, 0.5127]` | `0.5476` | `0.4205` | `0.4150` |
| **`HybridM0_with_Tranco`** | `HybridM0Model` (Producción `POST /check`) | `0.5000` | **`0.6176`** | **`0.9713`** | `0.3383` | `0.5019` `[0.4589, 0.5433]` | **`0.0132`** | `0.6617` | **`0.8077`** `[0.7808, 0.8330]` | **`0.8597`** | **`0.2202`** | **`0.2646`** |
| **`HybridM0_without_Tranco`** | `HybridM0Model` (Sin escudo Tranco) | `0.5000` | `0.6157` | `0.9535` | `0.3417` | `0.5025` `[0.4593, 0.5446]` | `0.0220` | `0.6583` | `0.7710` `[0.7424, 0.7988]` | `0.8330` | `0.2259` | `0.2654` |
| **`HybridM0_without_Tranco`** | `HybridM0Model` (Sin Tranco, $\tau=0.35$) | `0.3500` | **`0.6518`** | `0.9117` | `0.4300` | **`0.5844`** `[0.5439, 0.6223]` | `0.0551` | `0.5700` | `0.7710` `[0.7424, 0.7988]` | `0.8330` | `0.2259` | `0.2654` |

### 3.2 Desglose por Fuente de Procedencia (*Provenance Breakdown*)

El análisis por fuente revela por qué el modelo léxico puro `M0` sufre una caída severa de rendimiento global en la cohorte externa ($\text{F1} = 0.4879$, $\text{ROC-AUC} = 0.4859$), mientras que `HybridM0Model` mantiene $\text{ROC-AUC} = 0.8077$ (y $0.7710$ sin Tranco):

| Fuente Externa | Clase | $n$ | `M0_full` Tasa de Acierto | `M0_full` Error (FPR o FNR) | `M0_temporal` Tasa de Acierto | `HybridM0` (con Tranco) Tasa de Acierto | `HybridM0` (sin Tranco, $\tau=0.50$) Tasa de Acierto |
|---|---|---:|---:|---:|---:|---:|---:|
| **OpenPhish** (URLs completas activas) | Phishing (`1`) | $220$ | **`73.64%`** | `26.36%` (FNR) | **`80.00%`** | `57.27%` (`62.27%` a $\tau=0.35$) | `57.27%` (`62.27%` a $\tau=0.35$) |
| **CERT.PL** (dominios desnudos CSIRT) | Phishing (`1`) | $190$ | `28.95%` | `71.05%` (FNR) | `31.05%` | `20.00%` | `20.00%` |
| **Phishing Army** (dominios desnudos) | Phishing (`1`) | $190$ | `23.68%` | `76.32%` (FNR) | `24.74%` | `20.53%` | `21.58%` |
| **CISA `.gov`** (gobierno federal EE. UU.) | Legítima (`0`) | $200$ | **`98.50%`** | **`1.50%`** (FPR) | **`98.00%`** | **`100.00%`** (`0.0%` FPR) | **`100.00%`** (`0.0%` FPR) |
| **Majestic Million** (no vistos en `0.1.0`) | Legítima (`0`) | $54$ | `61.11%` | `38.89%` (FPR) | `59.26%` | **`90.74%`** (`9.26%` FPR) | **`90.74%`** (`9.26%` FPR) |
| **Hipo Universities** (`.edu`, `.ac.xx`, `www.`) | Legítima (`0`) | $200$ | **`6.00%`** | **`94.00%`** (FPR) | **`4.50%`** | **`99.50%`** (`0.5%` FPR) | **`97.50%`** (`2.5%` FPR) |

---

## 4. Hallazgo Forense Crítico: Aprendizaje de Atajos (*Shortcut Learning*) por `www.` y TLDs Académicos en `M0` vs. Normalización en `HybridM0Model`

> [!IMPORTANT]
> **Diagnóstico causal del fallo de `M0` en `hipo_universities` ($94.0\%$ FPR) y en dominios desnudos de phishing ($71\%–76\%$ FNR):**
> 1. **Sesgo de construcción en `0.1.0` (`samples.csv`):** En el dataset original `0.1.0`, las $99{,}994$ URLs legítimas se construyeron concatenando `https://` + dominio desnudo de Tranco (p. ej., `https://google.com/`), sin prefijo `www.` (`subdomain_count = 0`, `host_label_count = 2`). En cambio, las URLs de PhishTank eran URLs completas capturadas en vivo que frecuentemente incluían `www.` o subdominios (`subdomain_count >= 1`, `host_label_count >= 3`).
> 2. **Divergencia de código entre `src/phishguard_ml/features.py` y `src/phishguard_api/inference.py`:** El desarrollador de la extensión detectó este problema en producción y añadió en [`src/phishguard_api/inference.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/inference.py#L68-L70) las líneas:
>    ```python
>    if url_norm.startswith("http://www."):
>        url_norm = "http://" + url_norm[11:]
>    elif url_norm.startswith("https://www."):
>        url_norm = "https://" + url_norm[12:]
>    ```
>    Sin embargo, esta normalización **nunca se retroportó** a [`extract_url_features()`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/features.py#L127-L160) en el paquete de entrenamiento/evaluación científica `phishguard_ml`. Como consecuencia, cuando `M0` evalúa sitios universitarios reales con `www.` (p. ej., `http://www.espol.edu.ec/` o `http://www.harvard.edu/`), `subdomain_count` pasa de `0` a `1` y `host_label_count` sube a `3–4`, disparando una probabilidad media de phishing de **`0.9414`** ($94.0\%$ de falsos positivos).
> 3. **Incapacidad de `M0` ante feeds de dominios registrados sin ruta ni subdominio (`cert_pl`, `phishing_army`):** Dado que `M0` solo observa $11$ variables de autoridad (`authority_only`), un dominio de phishing sin subdominios ni dígitos/guiones anómalos es indistinguible léxicamente de un dominio raíz de Tranco, reduciendo el *recall* de `73.6%–80.0%` (en OpenPhish) a `23.7%–28.9%` (en CERT.PL / Phishing Army).

### Ablación controlada de canonicalización `www.` sobre modelos congelados (`02b_external_forensic_www_ablation.json` — Exploratorio)

Para demostrar empíricamente este mecanismo causal sin modificar ni reentrenar ningún peso de los modelos `.joblib`, evaluamos los mismos modelos congelados aplicando únicamente la normalización `strip_www()` de `inference.py`:

| Cohorte y Modelo Congelado | Condición de URL | Accuracy | Precision | Recall | F1-score | FPR Global | FPR en Hipo Univ. ($n=200$ / $n_{\text{CC}}=27$) | ROC-AUC | PR-AUC | Brier |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **$N=1{,}054$ — `M0_full_host_unseen`** | URL cruda (`raw`) | `0.4782` | `0.5527` | `0.4367` | `0.4879` | `0.4670` (`212/454`) | **`94.00%`** (`188/200`) | `0.4859` | `0.5594` | `0.4166` |
| **$N=1{,}054$ — `M0_full_host_unseen`** | Con `strip_www()` | **`0.6262`** | **`0.8503`** | `0.4167` | **`0.5593`** | **`0.0969`** (`44/454`) | **`10.00%`** (`20/200`) | **`0.7530`** | **`0.8135`** | **`0.2628`** |
| **$N_{\text{CC}}=104$ — `M0_CC`** | URL cruda (`raw`) | `0.4135` | `0.4255` | `0.3704` | `0.3960` | `0.5400` (`27/50`) | `88.89%` (`24/27`) | `0.3928` | `0.4343` | `0.5047` |
| **$N_{\text{CC}}=104$ — `M0_CC`** | Con `strip_www()` | **`0.6346`** | **`0.8636`** | `0.3519` | **`0.5000`** | **`0.0600`** (`3/50`) | **`0.00%`** (`0/27`) | **`0.7057`** | **`0.7674`** | **`0.3061`** |
| **$N_{\text{CC}}=104$ — `M1_CC` (URL+Infra)** | URL cruda (`raw`) | `0.3750` | `0.3659` | `0.2778` | `0.3158` | `0.5200` (`26/50`) | `92.59%` (`25/27`) | `0.4704` | `0.4969` | `0.5344` |
| **$N_{\text{CC}}=104$ — `M1_CC` (URL+Infra)** | Con `strip_www()` | **`0.5865`** | **`0.8235`** | `0.2593` | **`0.3944`** | **`0.0600`** (`3/50`) | **`7.41%`** (`2/27`) | **`0.8263`** | **`0.7988`** | **`0.3248`** |
| **$N_{\text{CC}}=104$ — `M2_CC` (URL+Infra+DOM)** | URL cruda (`raw`) | `0.5000` | `0.5192` | `0.5000` | `0.5094` | `0.5000` (`25/50`) | `92.59%` (`25/27`) | `0.5196` | `0.5379` | `0.4665` |
| **$N_{\text{CC}}=104$ — `M2_CC` (URL+Infra+DOM)** | Con `strip_www()` | **`0.7212`** | **`0.9630`** | `0.4815` | **`0.6420`** | **`0.0200`** (`1/50`) | **`3.70%`** (`1/27`) | **`0.9248`** | **`0.9423`** | **`0.2521`** |

---

## 5. Evaluación Multimodal en Vivo: *Intention-to-Evaluate* ($N = 240$) vs. *Complete-Case* ($N_{\text{CC}} = 104$)

Se ejecutó sondeo activo en vivo (resolución DNS + handshake TLS + transporte HTTP + descarga y parseo DOM HTML) sobre una subcohorte estratificada de $N_{\text{probe}} = 240$ URLs externas ($40$ por cada una de las $6$ fuentes: $120$ phishing y $120$ legítimas). **Ninguna muestra fallida fue excluida silenciosamente.**

### 5.1 Disponibilidad de Modalidades y Causas de No Accesibilidad ($N = 240$)

| Modalidad / Estado | Phishing ($n=120$) | Legítima ($n=120$) | Total ($N=240$) | Observación técnica |
|---|---:|---:|---:|---|
| **Infraestructura (`success`)** | $71$ ($59.17\%$) | $60$ ($50.00\%$) | **$131$ ($54.58\%$)** | Handshake DNS/TCP/HTTP completado |
| `blocked:dns_empty` (NXDOMAIN / sinkhole) | $34$ ($28.33\%$) | $54$ ($45.00\%$) | $88$ ($36.67\%$) | Dominios dados de baja o `.gov` sin registro A en raíz |
| `error:timeout` | $9$ ($7.50\%$) | $5$ ($4.17\%$) | $14$ ($5.83\%$) | Timeout de conexión ($5.0\text{ s}$) |
| `error:tls_error` / `network_error` | $6$ ($5.00\%$) | $1$ ($0.83\%$) | $7$ ($2.92\%$) | Certificados inválidos o rechazo TCP |
| **Contenido HTML DOM (`success`)** | $54$ ($45.00\%$) | $51$ ($42.50\%$) | **$105$ ($43.75\%$)** | Descarga HTTP 200 y parseo BeautifulSoup exitoso |
| `error:url_error` (DNS/conexión fallida) | $50$ ($41.67\%$) | $62$ ($51.67\%$) | $112$ ($46.67\%$) | Host inalcanzable por HTTP GET |
| `error:http_403` / `400` / `404` / `503` | $14$ ($11.67\%$) | $7$ ($5.83\%$) | $21$ ($8.75\%$) | Bloqueo WAF/Cloudflare o página caída |
| **Casos Completos (`Complete-Case`, $N_{\text{CC}}$)** | **$54$ ($45.00\%$)** | **$50$ ($41.67\%$)** | **$104$ ($43.33\%$)** | Ambas modalidades (`infra` y `content`) exitosas |

### 5.2 Tiempos de Latencia Medidos en Vivo durante el Sondeo Externo (`time.perf_counter`)
- **Sondeo de infraestructura (DNS + TLS + HTTP):** mediana ($P_{50}$) = **`1,117.86 ms`**, $P_{95}$ = **`3,573.40 ms`**.
- **Descarga de contenido (HTTP GET):** mediana ($P_{50}$) = **`665.92 ms`**, $P_{95}$ = **`3,578.35 ms`**.
- **Parseo de árbol DOM HTML (`analyze_html`):** mediana ($P_{50}$) = **`9.93 ms`**, $P_{95}$ = **`51.95 ms`**.

### 5.3 Resultados Multimodales en *Intention-to-Evaluate* ($N = 240$) y *Complete-Case* ($N_{\text{CC}} = 104$)

| Régimen y Modelo | $N$ | Cobertura | TN | FP | FN | TP | Precision | Recall | F1-score [IC 95%] | FPR | ROC-AUC [IC 95%] | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|---:|
| **ITE — `M0_ITE`** (URL cruda) | $240$ | `100.0%` | $66$ | $54$ | $73$ | $47$ | `0.4653` | `0.3917` | `0.4253` `[0.3426, 0.5062]` | `0.4500` | `0.4130` `[0.3436, 0.4872]` | `0.4768` |
| **ITE — `M1_ITE`** (URL cruda + Infra) | $240$ | `100.0%` | $64$ | $56$ | $74$ | $46$ | `0.4510` | `0.3833` | `0.4144` `[0.3286, 0.4934]` | `0.4667` | `0.5137` `[0.4389, 0.5909]` | `0.4954` |
| **ITE — `M2_ITE`** (URL cruda + Infra + DOM) | $240$ | `100.0%` | $62$ | $58$ | $80$ | $40$ | `0.4082` | `0.3333` | `0.3670` `[0.2828, 0.4464]` | `0.4833` | `0.5318` `[0.4557, 0.6061]` | `0.5037` |
| **CC — `M0_CC`** (URL cruda) | $104$ | `100.0%` | $23$ | $27$ | $34$ | $20$ | `0.4255` | `0.3704` | `0.3960` `[0.2653, 0.5091]` | `0.5400` | `0.3928` `[0.2798, 0.5028]` | `0.4343` |
| **CC — `M1_CC`** (URL cruda + Infra) | $104$ | `100.0%` | $24$ | $26$ | $39$ | $15$ | `0.3659` | `0.2778` | `0.3158` `[0.1839, 0.4330]` | `0.5200` | `0.4704` `[0.3434, 0.5819]` | `0.4969` |
| **CC — `M2_CC`** (URL cruda + Infra + DOM) | $104$ | `100.0%` | $25$ | $25$ | $27$ | $27$ | `0.5192` | `0.5000` | `0.5094` `[0.3800, 0.6218]` | `0.5000` | `0.5196` `[0.3887, 0.6387]` | `0.5379` |
| **CC — `M4_M2`** (Cascada 3 etapas, cruda) | $104$ | `100.0%` | $25$ | $25$ | $28$ | $26$ | `0.5098` | `0.4815` | `0.4952` `[0.3656, 0.6087]` | `0.5000` | `0.4815` `[0.3537, 0.6023]` | `0.4821` |
| **CC — `M5_M2`** (Selectivo en decididos, cruda) | $71$ | `68.27%` | $25$ | $24$ | $16$ | $6$ | `0.2000` | `0.2727` | `0.2308` `[0.0800, 0.3810]` | `0.4898` | `0.4406` `[0.3016, 0.5872]` | `0.3122` |
| **CC — `M0_CC`** (con `strip_www` — Exploratorio) | $104$ | `100.0%` | $47$ | $3$ | $35$ | $19$ | `0.8636` | `0.3519` | `0.5000` | `0.0600` | `0.7057` | `0.7674` |
| **CC — `M1_CC`** (con `strip_www` — Exploratorio) | $104$ | `100.0%` | $47$ | $3$ | $40$ | $14$ | `0.8235` | `0.2593` | `0.3944` | `0.0600` | `0.8263` | `0.7988` |
| **CC — `M2_CC`** (con `strip_www` — Exploratorio) | $104$ | `100.0%` | **$49$** | **$1$** | $28$ | $26$ | **`0.9630`** | `0.4815` | **`0.6420`** | **`0.0200`** | **`0.9248`** | **`0.9423`** |

> [!NOTE]
> **Observación sobre `M5_M2` en la cohorte externa ($N_{\text{CC}}=104$):** En la cascada sin normalizar `www.`, `M5_M2` se abstiene en $33$ de las $104$ muestras ($32$ de phishing y $1$ legítima, cobertura = $68.27\%$). Es decir, `M5` retiene acertadamente $32$ casos de phishing inciertos en `M2`, pero no retiene los $24$ falsos positivos de `hipo_universities` porque el atajo `www.` en `M0` produce probabilidades cercanas a $1.0$ con entropía $\mathcal{H}(p) \le 0.15$, saliendo tempranamente en la Etapa 0 (`26` paradas en `M0`, `28` en `M1`, `50` en `M2`).

---

## 6. Análisis de Contaminación por Pertenencia a Tranco Top-1M

De las $454$ URLs legítimas externas (ninguna de las cuales estaba en las $176{,}201$ muestras de `samples.csv`), $150$ ($33.04\%$) pertenecen al resto del listado completo Tranco Top-1M (`tranco_top1m.csv`), mientras que $304$ ($66.96\%$) no aparecen en absoluto en Tranco Top-1M (principalmente dominios gubernamentales `.gov` municipales/federales y universidades regionales). De las $600$ URLs de phishing externas, $3$ ($0.50\%$, todas de OpenPhish alojadas en servicios legítimos comprometidos/compartidos) están en Tranco Top-1M:

| Modelo | FPR cuando el dominio legítimo ESTÁ en Tranco ($n=150$) | FPR cuando el dominio legítimo NO está en Tranco ($n=304$) | Interpretación |
|---|---:|---:|---|
| `M0_full_host_unseen` | `82.67%` | `28.95%` | Más alto dentro de Tranco porque `92/150` son universidades Hipo con prefijo `www.` |
| `HybridM0_with_Tranco` | **`0.00%`** | **`1.97%`** (`6/304`) | El escudo Tranco garantiza `0%` FPR en el Top-1M, pero incluso fuera de Tranco el FPR es solo `1.97%` |
| `HybridM0_without_Tranco` | **`2.67%`** (`4/150`) | **`1.97%`** (`6/304`) | Al desactivar Tranco, `HybridM0Model` mantiene `97.33%` de especificidad gracias a `strip_www()` y las reglas heurísticas |

---

## 7. Escenarios de Prevalencia Operativa ($\pi \in \{50\%, 10\%, 1\%, 0.1\%\}$)

Aplicando el teorema de Bayes sobre la sensibilidad ($\text{TPR}$) y tasa de falsos positivos ($\text{FPR}$) medidas en la cohorte externa ($N = 1{,}054$), se proyectó la precisión operativa ($\text{PPV}$), el $\text{F1}$ proyectado y el volumen esperado de falsas alarmas por cada $10{,}000$ URLs inspeccionadas:

| Modelo | Prevalencia ($\pi$) | Precision Proyectada ($\text{PPV}$) | Recall ($\text{TPR}$) | F1 Proyectado | Falsos Positivos / $10{,}000$ URLs | Falsos Negativos / $10{,}000$ URLs |
|---|---:|---:|---:|---:|---:|---:|
| **`M0_full_host_unseen`** (crudo) | `50.0%` | `0.4832` | `0.4367` | `0.4588` | $2{,}334.8$ | $2{,}816.7$ |
| **`M0_full_host_unseen`** (crudo) | `10.0%` | `0.0941` | `0.4367` | `0.1549` | $4{,}202.6$ | $563.3$ |
| **`M0_full_host_unseen`** (crudo) | `1.0%` | `0.0094` | `0.4367` | `0.0183` | $4{,}622.9$ | $56.3$ |
| **`M0_full_host_unseen`** (crudo) | `0.1%` | `0.0009` | `0.4367` | `0.0019` | $4{,}664.9$ | $5.6$ |
| **`HybridM0_with_Tranco`** | `50.0%` | **`0.9624`** | `0.3383` | **`0.5007`** | **$66.1$** | $3{,}308.3$ |
| **`HybridM0_with_Tranco`** | `10.0%` | **`0.7399`** | `0.3383` | **`0.4643`** | **$118.9$** | $661.7$ |
| **`HybridM0_with_Tranco`** | `1.0%` | **`0.2055`** | `0.3383` | **`0.2557`** | **$130.8$** | $66.2$ |
| **`HybridM0_with_Tranco`** | `0.1%` | **`0.0250`** | `0.3383` | **`0.0465`** | **$132.0$** | $6.6$ |
| **`HybridM0_without_Tranco`** | `50.0%` | `0.9394` | `0.3417` | `0.5011` | $110.1$ | $3{,}291.7$ |
| **`HybridM0_without_Tranco`** | `10.0%` | `0.6328` | `0.3417` | `0.4438` | $198.2$ | $658.3$ |
| **`HybridM0_without_Tranco`** | `1.0%` | `0.1355` | `0.3417` | `0.1940` | $218.1$ | $65.8$ |
| **`HybridM0_without_Tranco`** | `0.1%` | `0.0153` | `0.3417` | `0.0293` | $220.0$ | $6.6$ |

---

## 8. Comparación Explícita: Conjunto Histórico (`0.1.0`) vs. Cohorte Externa Independiente

| Métrica / Propiedad | Conjunto Histórico (`host_unseen` $N=691$ / $N=20{,}974$) | Cohorte Externa Independiente ($N=1{,}054$ / $N_{\text{CC}}=104$) | Cambio Absoluto ($\Delta$) | Explicación Científica |
|---|---:|---:|---:|---|
| **`M0_full` F1-score** | `0.8582` ($N=20{,}974$) | `0.4879` (crudo) / `0.5593` (`strip_www`) | `-0.3703` / `-0.2989` | Atajo de `www.` en `hipo_universities` + baja sensibilidad en dominios desnudos (`cert_pl`, `phishing_army`) |
| **`M0_full` ROC-AUC** | `0.9378` ($N=20{,}974$) | `0.4859` (crudo) / **`0.7530`** (`strip_www`) | `-0.4519` / `-0.1848` | Al corregir la discrepancia de `www.`, `M0` recupera poder discriminativo significativo (`0.7530`) |
| **`M2_CC` ROC-AUC** | `0.9866` ($N=691$) | `0.5196` (crudo) / **`0.9248`** (`strip_www`) | `-0.4670` / **`-0.0618`** | Al controlar el artefacto `www.` heredado de `M0`, la fusión multimodal `M2` (URL+Infra+DOM) mantiene `ROC-AUC = 0.9248` y `PR-AUC = 0.9423` en datos externos en vivo |
| **`M2_CC` FPR** | `0.0096` (`0.96%`, $N=691$) | `0.5000` (crudo) / **`0.0200`** (`2.00%`, `strip_www`) | `+0.4904` / **`+0.0104`** | $24$ de los $25$ FPs crudos en $N_{\text{CC}}=104$ se debieron exclusivamente al prefijo `www.` en `hipo_universities` |
| **`HybridM0` Precision** | `0.9866` ($N=691$) | **`0.9713`** (con Tranco) / **`0.9535`** (sin Tranco) | `-0.0153` / `-0.0331` | La arquitectura híbrida de la extensión preserva alta precisión y bajo FPR (`1.32%–2.20%`) fuera de distribución |
| **`HybridM0` Recall** | `0.8647` ($N=691$) | `0.3383` (`57.27%` en OpenPhish; `62.27%` a $\tau=0.35$) | `-0.5264` (`-0.2920` en OpenPhish) | Caída concentrada en listas de dominios registrados desnudos (`cert_pl`, `phishing_army`) donde no hay ruta ni subdominio sospechoso |
