# FASE III: EVALUACIÓN REAL DE LA EXTENSIÓN Y DEL SOFTWARE OPERATIVO

**Fecha de ejecución:** 2026-10-12 *(corregido 2026-10-14: la fecha declarada 2026-04-12 era un error tipográfico; la ejecución real es de 2026-10-12 UTC, verificado por los captured_at de los manifiestos de artefactos y por los tiempos de los archivos)*  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Script de evaluación:** [fase2_03_extension_real.py](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_03_extension_real.py)  
**Artefactos generados:**
- [03_extension_real_results.json](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase3_extension/03_extension_real_results.json)
- [03_per_request_extension_and_cascade_log.csv](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase3_extension/03_per_request_extension_and_cascade_log.csv) ($N = 691$ registros individuales con latencias monotónicas y decisiones para Configuraciones A, B y C)

---

## 1. Arquitectura Operativa y Separación Estricta de las Tres Configuraciones

De acuerdo con el protocolo de auditoría de software, se instrumentó y evaluó el servidor FastAPI real ([`src/phishguard_api/server.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/server.py)) y el contrato del *Service Worker* de la extensión Chromium ([`extension/background.js`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js)), separando estrictamente tres configuraciones operativas:

1. **Configuración A (Extensión de Producción Actual sin modificar — `POST /check`):**
   - El *Service Worker* `extension/background.js` invoca exclusivamente `POST http://localhost:8080/check` con un `AbortSignal.timeout(6000)` ($6{,}000\text{ ms}$). Incluso si el usuario configura `/analyses` en `chrome.storage.local`, las líneas 50–53 de `background.js` reescriben forzosamente el endpoint a `http://localhost:8080/check`.
   - En el backend, `POST /check` ejecuta [`validate_url_ssrf_safety(url)`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/policy.py#L58-L86) seguido de [`predict_hybrid(url, user_country)`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/hybrid_model.py#L40-L317), que combina el modelo léxico `M0` ($11$ variables), reputación Tranco Top-1M, similitud de marca Levenshtein/Jaro, análisis de homógrafos y $15$ reglas heurísticas en [`DetectionRules`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/detection_rules.py).
2. **Configuración B (Cascada Experimental mediante API — `UnifiedModelManager` + `engine.py` / `worker.py`):**
   - Utiliza la infraestructura de inferencia escalonada en [`src/phishguard_api/inference.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/inference.py), el orquestador [`src/phishguard_orchestrator/engine.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_orchestrator/engine.py) y el consumidor asíncrono [`src/phishguard_api/worker.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/worker.py) (`POST /analyses`).
   - Se auditaron tanto el comportamiento del código actual del orquestador (`B1` y `B2`) como la cascada calibrada de tres etapas `M0 -> M1 -> M2` (`B3`).
3. **Configuración C (Integración Experimental Extensión $\leftrightarrow$ Cascada `HybridM0 -> M1 -> M2/M5` en rama de pruebas):**
   - Conecta el contrato de `POST /check` con la cascada multimodal `M0 -> M1 -> M2` sin reemplazar silenciosamente la Configuración A. La Etapa 0 ejecuta `HybridM0Model`; si la probabilidad cae en la banda de incertidumbre ($0.12 < p < 0.80$), escala a `M1` (DNS/TLS/HTTP) y `M2` (HTML DOM), mapeando las abstenciones de `M5` ($\mathcal{H}(p_{M2}) > 0.65$) al estado `decision = "warning"` (insignia `?` ámbar en la extensión).

---

## 2. Hallazgos de Auditoría de Software en el Código Operativo (6 Discrepancias Descubiertas)

La inspección línea por línea y la ejecución en vivo sobre `server.py`, `worker.py`, `inference.py`, `hybrid_model.py` y `homoglyphs.py` revelaron **seis defectos de implementación críticos** no documentados en el manuscrito original:

| # | Componente y Ubicación Exacta | Defecto / Discrepancia Descubierta | Impacto Operativo Medido |
|---|---|---|---|
| **1** | [`extension/background.js#L35`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js#L35) vs. [`detection_rules.py#L222`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/detection_rules.py#L222) | **Desajuste de Timeouts Cliente/Servidor ($6\text{ s}$ vs. $8\text{ s}$):** `background.js` aborta `POST /check` a los $6{,}000\text{ ms}$ (`AbortSignal.timeout(6000)`), pero `DetectionRules.analyze()` lanza hilos WHOIS y GeoIP con timeout de $8{,}000\text{ ms}$. | En caché fría (`A1`), el **$5.0\%$ de las peticiones ($1/20$, máx $= 10{,}996\text{ ms}$, $P_{99} = 9{,}520.8\text{ ms}$)** supera los $6{,}000\text{ ms}$, provocando que la extensión aborte en silencio (*fail-open* pasivo en `background.js` línea 194). |
| **2** | [`server.py#L187`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/server.py#L187) y [`policy.py#L78`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/policy.py#L78) | **Resolución DNS bloqueante en el bucle de eventos asíncrono:** `validate_url_ssrf_safety(url)` invoca `socket.getaddrinfo(host, None)` de forma síncrona dentro de `async def check_url()` sin caché ni `asyncio.to_thread`. | En dominios de phishing inactivos (`NXDOMAIN` lento), bloquea el hilo principal de FastAPI entre $400\text{ ms}$ y $2{,}500\text{ ms}$ por petición antes de llegar al modelo ML. |
| **3** | [`homoglyphs.py#L106`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/homoglyphs.py#L106) vs. [`hybrid_model.py#L163`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/hybrid_model.py#L163) y [`background.js#L140`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js#L140) | **Código muerto por discrepancia de claves JSON en Homógrafos + falta de decodificación Punycode:** `analyze_homoglyphs()` devuelve `"homoglyph_brand_spoofing_detected"` y `"closest_brand_target"`, pero `HybridM0Model` consulta `homoglyphs_data.get("is_spoofing")` y `background.js` lee `result.homoglyphs?.is_spoofing` y `target_brand`. Además, `to_visual_skeleton()` no decodifica `xn--` (IDNA) antes de buscar caracteres cirílicos. | La rama `CASE A` de `HybridM0Model` (`final_prob = 0.97`) **jamás se ejecuta**. Al probar `https://www.xn--pple-43d.com/login` (`аpple.com` cirílico en Punycode), `POST /check` devolvió **`decision: "legitimate"`, `probability: 0.0935`**. |
| **4** | [`engine.py#L31-L36`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_orchestrator/engine.py#L31-L36) | **Confusión entre umbral de escalamiento ($\mathcal{H}=0.20$) y umbral de abstención final ($\mathcal{H}=0.65$):** `decide_next()` usa un único `uncertainty_threshold = 0.20` en todas las etapas y exige `confidence >= 0.80` incluso tras agotar las $4$ modalidades. | Cualquier muestra cuya probabilidad final en `M3` esté en $(0.031, 0.969)$ es forzada a `"abstain"` (`decision = "uncertain"`), disparando la abstención a **$8.54\%$ ($59/691$)** frente al $4.20\%$ ($29/691$) de `M5` calibrado, y usando umbral fijo $0.50$ ($\text{FPR} = 4.00\%$ vs. $0.40\%$). |
| **5** | [`worker.py#L154-L155`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/worker.py#L154-L155) y [`#L251`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/worker.py#L251) | **Salto fuera de orden de `M0` a `M3` con vectores vacíos:** Cuando `M0` decide `probability >= 0.50`, `worker.py` fuerza `action = "visual"` (`capture_for_blocked_site`) sin haber ejecutado `infrastructure` ni `content`, llamando a `predict_m3()` con diccionarios vacíos `{}` ($0.0$ en las $23$ variables de infraestructura y $16$ de contenido). | Corrompe la entrada de `M3` y obliga a ejecutar etapas posteriores en orden inverso (`url -> visual -> infrastructure -> content`), elevando el consumo medio a $2.33$ modalidades. |
| **6** | [`worker.py#L243-L249`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/worker.py#L243-L249) | **Sobrescritura de `M2` por probabilidad LLM no calibrada:** En la etapa `content`, si el sandbox devuelve `probability` del LLM, `worker.py` reemplaza a `predict_m2()` con la probabilidad cruda del LLM, relegando el modelo `M2` calibrado a un mero *fallback* cuando falla la API de Groq. | Desvirtúa la calibración de Platt/isotónica de la Etapa 2 cuando la API de Groq está activa. |

---

## 3. Mediciones de Latencia Extremo a Extremo (`time.perf_counter`)

Todas las mediciones se realizaron con reloj monotónico (`time.perf_counter` / `time.perf_counter_ns`) sobre el servidor FastAPI real:

| Configuración y Régimen de Prueba | $N$ | Mediana ($P_{50}$) [ms] | Media [ms] | DE (SD) [ms] | $P_{90}$ [ms] | $P_{95}$ [ms] | $P_{99}$ [ms] | Mín [ms] | Máx [ms] | $>6{,}000\text{ ms}$ (Aborto Extensión) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Config A1 (`POST /check` Caché Fría + DNS/WHOIS/GeoIP en Vivo)** | $20$ | **`994.45`** | `1,623.22` | `2,296.37` | `1,788.60` | **`3,620.06`** | **`9,520.85`** | `393.81` | `10,996.05` | **$1 / 20$ (`5.00%`)** |
| **Config A1-Warm (`POST /check` Caché WHOIS/GeoIP Tibia + DNS SO)** | $20$ | **`17.11`** | `30.03` | `54.45` | `23.10` | `38.35` | `216.51` | `14.16` | `261.05` | $0 / 20$ (`0.00%`) |
| **Config A2 (`POST /check` Sostenido HTTP Interno $N=691$)** | $691$ | **`50.57`** | `55.46` | `19.28` | `79.48` | `96.94` | `121.40` | `20.95` | `145.72` | $0 / 691$ (`0.00%`) |
| **Config A2 (`POST /check` Sostenido HTTP Externo $N=240$)** | $240$ | **`16.51`** | `16.30` | `2.41` | `18.83` | `20.06` | `22.38` | `11.48` | `28.06` | $0 / 240$ (`0.00%`) |
| **Config A3 (`analysisCache` Map en `background.js` / `BloomFilter`)** | $20{,}000$ | **`0.0011`** | `0.0014` | `0.0009` | `0.0021` | `0.0026` | `0.0042` | `0.0004` | `0.0890` | $0$ (`0.00%`) |
| **Config B3 (Cascada API Calibrada `M0->M1->M2` en $N=691$)** | $691$ | **`1,204.72`** | `1,360.71` | `1,125.56` | `2,768.85` | `3,388.30` | `4,939.78` | `7.52` | `7,150.77` | $1 / 691$ (`0.14%`) |
| **Config C (Integración Experimental `HybridM0->M1->M2` en $N=691$)** | $691$ | **`51.51`** | **`306.14`** | `551.00` | `1,061.07` | `1,418.85` | `2,447.45` | `20.95` | `5,078.17` | $0 / 691$ (`0.00%`) |
| **Config C (Integración Experimental `HybridM0->M1->M2` en $N=240$ Ext.)** | $240$ | **`68.33`** | **`681.71`** | `1,204.56` | `2,679.85` | `3,118.90` | `5,352.30` | `12.44` | `7,199.51` | $2 / 240$ (`0.83%`) |

> [!TIP]
> **Ventaja de latencia de la Configuración C frente a la Configuración B3:** Al utilizar `HybridM0Model` en la Etapa 0, el $73.81\%$ de las peticiones en $N=691$ ($510/691$) y el $75.83\%$ en $N=240$ externo ($182/240$) se resuelven en la Etapa 0 con una mediana de **`51.51 ms`** (`68.33 ms` en externo), escalando a red/DOM únicamente el $\sim 25\%$ de dominios desconocidos. Esto reduce la latencia mediana extremo a extremo en **$23.4\times$** respecto a la cascada API pura `B3` (`51.51 ms` vs. `1,204.72 ms`).

---

## 4. Comparación de Efectividad: Configuraciones A, B y C

### 4.1 Cohorte Interna Multimodal ($N = 691$: $500$ legítimas, $191$ phishing)

| Configuración / Variante | Cobertura | Modalidades Medias ($\bar{m}$) | TN | FP | FN | TP | Accuracy | Precision | Recall | F1-score | FPR | FNR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Config A (`POST /check` con Tranco)** | `100.00%` | `1.0000` | **$500$** | **$0$** | $41$ | $150$ | `0.9407` | **`1.0000`** | `0.7853` | `0.8798` | **`0.0000`** | `0.2147` | **`0.9904`** | `0.9786` |
| **Config A (`HybridM0` sin Tranco, $\tau=0.50$)** | `100.00%` | `1.0000` | $498$ | $2$ | $42$ | $149$ | `0.9363` | `0.9868` | `0.7801` | `0.8713` | `0.0040` | `0.2199` | `0.9675` | `0.9457` |
| **Config A (`HybridM0` sin Tranco, $\tau=0.35$)** | `100.00%` | `1.0000` | $471$ | $29$ | $17$ | $174$ | `0.9334` | `0.8571` | `0.9110` | `0.8832` | `0.0580` | `0.0890` | `0.9675` | `0.9457` |
| **Config B1 (`engine.py` `run_adaptive` forzado $\tau=0.50$)** | `100.00%` | `2.1114` | $480$ | $20$ | $18$ | $173$ | `0.9450` | `0.8964` | `0.9058` | `0.9010` | `0.0400` | `0.0942` | `0.9710` | `0.9440` |
| **Config B1 (`engine.py` en decididos, $59$ abst.)** | `91.46%` | `2.1114` | $459$ | $1$ | $11$ | $161$ | `0.9810` | `0.9938` | `0.9360` | `0.9641` | `0.0022` | `0.0640` | `0.9743` | `0.9508` |
| **Config B2 (`worker.py` con salto M0$\to$M3 forzado)** | `100.00%` | `2.3329` | $480$ | $20$ | $18$ | $173$ | `0.9450` | `0.8964` | `0.9058` | `0.9010` | `0.0400` | `0.0942` | `0.9716` | `0.9578` |
| **Config B3 (Cascada API Calibrada `M4` forzado)** | `100.00%` | `2.0839` | $497$ | $3$ | $26$ | $165$ | `0.9580` | `0.9821` | `0.8639` | `0.9192` | `0.0060` | `0.1361` | `0.9770` | `0.9719` |
| **Config B3 (Cascada API Calibrada `M5` Fail-Closed)** | `96.96%` (`100%` c/alerta) | `2.0839` | $493$ | $7$ | **$18$** | **$173$** | **`0.9638`** | `0.9611` | **`0.9058`** | **`0.9326`** | `0.0140` | **`0.0942`** | `0.9770` | `0.9719` |
| **Config C (Integración Experimental Forzada)** | `100.00%` | **`1.3415`** | **$500$** | **$0$** | $33$ | $158$ | `0.9522` | **`1.0000`** | `0.8272` | `0.9054` | **`0.0000`** | `0.1728` | `0.9901` | **`0.9838`** |
| **Config C (Integración Experimental Fail-Closed)** | `100.00%` | **`1.3415`** | **$500$** | **$0$** | **$29$** | **$162$** | **`0.9580`** | **`1.0000`** | **`0.8482`** | **`0.9178`** | **`0.0000`** | **`0.1518`** | `0.9901` | **`0.9838`** |

### 4.2 Cohorte Externa Sondeada en Vivo ($N = 240$ ITE y $N_{\text{CC}} = 104$ Complete-Case)

| Configuración / Variante | Cohorte Externa | $N$ | TN | FP | FN | TP | Precision | Recall | F1-score | FPR | ROC-AUC | PR-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Config A (`POST /check`)** | ITE Externo | $240$ | $114$ | $6$ | $91$ | $29$ | `0.8286` | `0.2417` | `0.3742` | `0.0500` | `0.6643` | `0.6952` |
| **Config C (`HybridM0 -> M1 -> M2`)** | ITE Externo | $240$ | $113$ | $7$ | **$86$** | **$34$** | `0.8293` | **`0.2833`** | **`0.4224`** (`+0.0482`) | `0.0583` | `0.6584` | `0.6952` |
| **Config A (`POST /check`)** | Complete-Case Externo | $104$ | **$50$** | **$0$** | $37$ | $17$ | **`1.0000`** | `0.3148` | `0.4789` | **`0.0000`** | `0.8380` | `0.8726` |
| **Config B (`M4_M2` crudo sin normalizar `www.`)** | Complete-Case Externo | $104$ | $25$ | $25$ | $28$ | $26$ | `0.5098` | `0.4815` | `0.4952` | `0.5000` | `0.4815` | `0.4821` |
| **Config C (`HybridM0 -> M1 -> M2`)** | Complete-Case Externo | $104$ | **$50$** | **$0$** | **$33$** | **$21$** | **`1.0000`** | **`0.3889`** | **`0.5600`** (`+0.0811`) | **`0.0000`** | **`0.8380`** | **`0.8736`** |

---

## 5. Batería de 12 Pruebas de Resiliencia, Seguridad SSRF y Casos Borde en FastAPI

| Caso de Prueba (`test_name`) | Método y Ruta | Payload / URL Probada | Código HTTP | Latencia [ms] | Comportamiento Observado y Diagnóstico |
|---|---|---|---:|---:|---|
| `health_endpoint` | `GET /health` | — | `200` | `0.713` | `{"status": "ok"}` — Operativo |
| `ssrf_loopback_127` | `POST /check` | `http://127.0.0.1:8080/admin` | **`403`** | `2.246` | Bloqueado por `validate_url_ssrf_safety` (`ssrf_blocked: non_global_address`) |
| `ssrf_aws_metadata` | `POST /check` | `http://169.254.169.254/latest/meta-data/` | **`403`** | `0.799` | Bloqueado correctamente contra robo de credenciales cloud IMDSv1 |
| `ssrf_private_lan` | `POST /check` | `http://192.168.1.1/login` | **`403`** | `0.812` | Bloqueado correctamente para subredes privadas RFC 1918 |
| `invalid_scheme_javascript` | `POST /check` | `javascript:alert(1)` | **`422`** | `0.711` | Rechazado (`Only HTTP/HTTPS schemes are allowed`) |
| `invalid_scheme_ftp` | `POST /check` | `ftp://files.example.com/pub` | **`422`** | `0.624` | Rechazado (`Only HTTP/HTTPS schemes are allowed`) |
| `empty_url` | `POST /check` | `"   "` | **`400`** | `0.633` | Rechazado (`URL invalida`) |
| `oversized_url_9000_chars` | `POST /check` | `https://example.com/` + $8{,}200$ `'a'` | **`400`** | `0.688` | Rechazado por límite de longitud $> 8{,}192$ bytes |
| `idn_punycode_homoglyph_apple` | `POST /check` | `https://www.xn--pple-43d.com/login` | `200` | `395.801` | **FALLO DETECTADO:** Clasificado como `"legitimate"` ($p=0.0935$) por falta de `idna.decode` y clave `"is_spoofing"` en `homoglyphs.py` |
| `subdomain_brand_spoofing_paypal` | `POST /check` | `https://paypal.com.verify-account-update.tk/signin` | `200` | `597.095` | **DETECTADO:** `"decision": "phishing"`, $p=0.8800$, marca `"paypal"` e indicadores `.tk` + `financial_phishing` |
| `regional_bank_collision_bcp_pe` | `POST /check` | `https://www.bcp.com/` (`user_country="PE"`) | `200` | `1,374.181` | **SUGERENCIA REGIONAL ACTIVA:** Devuelve `local_suggestions: [{"brand_name": "Banco de Credito del Peru", "suggested_domain": "viabcp.com"}]` |
| `legacy_analyze_endpoint` | `POST /analyze` | `https://example.com/` | `200` | `0.629` | Devuelve stub estático `{"decision": "uncertain", "probability_phishing": 0.5, "mode": "legacy-compatibility"}` |
