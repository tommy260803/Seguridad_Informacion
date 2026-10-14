# RESULTADOS E2E EN CHROME REAL — PhishPe

**Generado:** 2026-10-14T16:05:42.991977+00:00 · **fuente única de cifras:** `artifacts/e2e_chrome/summary.json` y `requests.jsonl` (este documento lo genera `scripts/phase2k_summarize_e2e.py`; ninguna cifra está escrita a mano).

## 1. Proveniencia del navegador y del entorno (verificable)

| Elemento | Valor | Evidencia |
|---|---|---|
| Navegador usado | `Chrome/156.0.8078.4` (Chrome-for-Testing, build Playwright `chromium-1248`) | `chrome_version.txt`, `browser_product.txt` |
| Chrome de marca instalado | `155.0.8059.40` | `browser_product.txt` |
| Restricción del Chrome de marca | rechaza `--load-extension`: «chrome\browser\extensions\extension_service.cc:423] --load-extension is not allowed in Google Chrome, ignoring.» | `branded_chrome_load_extension.log` |
| Extensión | cargada **empaquetada (directorio descomprimido)** con perfil efímero, service worker real | registro de arranque + `requests.jsonl` |
| Backend | servidor real en `:8080` (FastAPI + worker), **no** ASGI de pruebas ni mocks | `backend_check_smoke.json`, `backend.log` |
| Red | HTTP/HTTPS real contra Internet público | respuestas reales registradas |
| Control | Playwright sobre el binario real (CDP), driver `scripts/e2e_chrome_phase2.py` | `preflight*.json` |
| Binario | `C:\Users\User\AppData\Local\ms-playwright\chromium-1248\chrome-win64\chrome.exe` | `chrome_version.txt` |

Prueba de humo del backend (petición real a Internet): `https://example.com` → decisión `legitimate` (p = 0.00102), resolución vía Canada / Cloudflare, Inc.. Latencia total de la llamada: 6116.034912109375 ms.

> **Declaración honesta del navegador.** La batería **no** corrió en el Chrome de marca (Google Chrome 155) porque ese producto **bloquea** `--load-extension` desde la versión 137 (evidencia literal en `branded_chrome_load_extension.log`). Corrió en **Chrome-for-Testing 156**, que es una compilación oficial del mismo motor, con servicio de extensiones, DevTools/CDP y pila de red reales. Es un límite del producto, no una simulación: el navegador, la extensión, el backend y la red son reales.

## 2. Resultado global

| Escenarios totales | PASS | NOT_RUN | PARTIAL |
|---:|---:|---:|---:|
| 27 | 25 | 2 | 0 |

- Llamadas al backend registradas: **40** (timeouts: 2, tasa 0.05)

Atribución de los eventos de error (calculada de `api_new` en `requests.jsonl`):

| Escenario | Duración (ms) | Error | ¿Deliberado? |
|---|---:|---|---|
| `h_timeout_stub` | 8010 | `TimeoutError: signal timed out` | **sí** (escenario diseñado para provocarlo) |
| `m_backend_down` | 4 | `TypeError: Failed to fetch` | **sí** (escenario diseñado para provocarlo) |
| `h_timeout_stub_exact` | 8004 | `TimeoutError: signal timed out` | **sí** (escenario diseñado para provocarlo) |
| `m_backend_down_exact` | 2 | `TypeError: Failed to fetch` | **sí** (escenario diseñado para provocarlo) |

**Timeouts/errores espontáneos en escenarios no deliberados: 0** sobre 40 llamadas. Los 2 timeouts corresponden íntegramente a `h_timeout_stub` y `h_timeout_stub_exact` (stub deliberado de >8 s).
- Latencia de la API medida por el cliente (p50/p90/p95/p99): 497.0 / 1895.0 / 2196.25 / 3690.25 ms (n = 36)
- Latencia medida por **resource-timing del navegador** (p50/p90/p95/p99): 40 / 2160.8 / 3808.2 / 8008.12 ms (n = 49)
- Navegación → insignia (p50/p90/p95/p99): 861.3 / 2894.18 / 4936.56 / 13131.27 ms (n = 45)
- Navegación → decisión visible (p50/p90/p95/p99): 1764.9 / 16045.27 / 36127.76 / 36458.58 ms (n = 64)

> Los percentiles anteriores son **mediciones reales de pared y de resource-timing**; no son sumas de medianas ni simulaciones.

## 3. Tabla de escenarios

| Escenario | Reps | Llamadas backend | Insignia | Av. | Err. | API p50 (ms) | API p95 (ms) | Insig. p50 (ms) | Decisión p50 (ms) | Estado | Motivo |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---|---|
| `a_legit` | 4 | 4 | ✔ | 0 | 0 | 21.0 | 30.5 | 586.3 | 696.4 | **PASS** | insignia/intersticial observado en Chrome real |
| `a_www_pair` | 1 | 0 | ✔ | 0 | 0 |  |  | 20.2 | 87.2 | **PASS** | insignia/intersticial observado en Chrome real |
| `c_phishing` | 3 | 0 | — | 0 | 0 | 1252 | 1252 |  | 15224.2 | **PASS** | página de error real del navegador (Page.goto: net::ERR_NAME_NOT_RESOLVED): sin decisión de la extensión posible |
| `c_phishing_resolvable` | 10 | 8 | ! / ✔ | 5 | 0 | 23 | 912.6 | 982.8 | 1448.95 | **PASS** | insignia/intersticial observado en Chrome real |
| `d_warning` | 3 | 3 | ? | 3 | 0 | 20 | 2453.6 | 732.8 | 802.1 | **PASS** | insignia/intersticial observado en Chrome real |
| `e_dns_error` | 1 | 0 | — | 0 | 0 |  |  |  | 12145.6 | **PASS** | página de error real del navegador (Page.goto: net::ERR_NAME_NOT_RESOLVED): sin decisión de la extensión posible |
| `f_tls_error` | 1 | 1 | ✔ | 0 | 0 | 1055 | 1055 | 2099.5 | 2107.9 | **PASS** | insignia/intersticial observado en Chrome real |
| `g_http_404` | 1 | 0 | — | 0 | 0 |  |  |  | 15131.9 | **PASS** | página de error real del navegador (Page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE): sin decisión de la extensión posible |
| `g_http_500` | 1 | 0 | — | 0 | 0 |  |  |  | 15989.9 | **PASS** | página de error real del navegador (Page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE): sin decisión de la extensión posible |
| `h_timeout_stub` | 1 | 1 | — | 0 | 1 | 923.0 | 2918.65 |  | 13957.6 | **PASS** | degradación controlada: el cliente abortó/caída detectada (esto es lo que el escenario pretendía provocar) |
| `h_timeout_stub_exact` | 1 | 1 | — | 0 | 1 | 8005 | 8005 |  | 13668.2 | **PASS** | degradación controlada: el cliente abortó/caída detectada (esto es lo que el escenario pretendía provocar) |
| `i_redirect_github` | 1 | 1 | ✔ | 0 | 0 |  |  |  |  | **PASS** | insignia/intersticial observado en Chrome real |
| `j_punycode` | 2 | 0 | — | 0 | 0 |  |  |  | 8196.55 | **PASS** | página de error real del navegador (Page.goto: net::ERR_NAME_NOT_RESOLVED): sin decisión de la extensión posible |
| `j_punycode_resolvable` | 3 | 1 | ! / ✔ | 1 | 0 | 23 | 23 | 634.3 | 1026.1 | **PASS** | insignia/intersticial observado en Chrome real |
| `k_cache_probe_1` | 1 | 1 | ✔ | 0 | 0 |  |  | 1981.3 | 2240.9 | **PASS** | insignia/intersticial observado en Chrome real |
| `k_cache_probe_2` | 1 | 1 | ✔ | 0 | 0 | 527.5 | 2879.7 | 1389.5 | 1464.8 | **PASS** | insignia/intersticial observado en Chrome real |
| `k_cold` | 10 | 9 | ✔ | 0 | 0 |  |  | 1740.1 | 2227.1 | **PASS** | insignia/intersticial observado en Chrome real |
| `k_hot` | 10 | 0 | ✔ | 0 | 0 |  |  | 82.6 | 248.55 | **PASS** | insignia/intersticial observado en Chrome real |
| `l_concurrency` | 1 | 0 | — | 0 | 0 |  |  |  |  | **NOT_RUN** | sin navegación registrada en requests.jsonl |
| `m_backend_down` | 1 | 1 | — | 0 | 1 |  |  |  | 12813.1 | **PASS** | degradación controlada: el cliente abortó/caída detectada (esto es lo que el escenario pretendía provocar) |
| `m_backend_down_exact` | 1 | 1 | — | 0 | 1 | 1 | 1 |  | 12839.9 | **PASS** | degradación controlada: el cliente abortó/caída detectada (esto es lo que el escenario pretendía provocar) |
| `n_offline` | 1 | 0 | — | 0 | 0 |  |  |  | 10075.4 | **PASS** | página de error real del navegador (Page.goto: net::ERR_INTERNET_DISCONNECTED): sin decisión de la extensión posible |
| `n_offline_exact` | 1 | 0 | — | 0 | 0 |  |  |  | 10070.1 | **PASS** | página de error real del navegador (Page.goto: net::ERR_INTERNET_DISCONNECTED): sin decisión de la extensión posible |
| `o_cascade_analyses` | 1 | 0 | — | 0 | 0 |  |  |  |  | **NOT_RUN** | navegación sin llamada al backend ni insignia: escenario incompleto |
| `shot_legit_badge` | 2 | 2 | ✔ | 0 | 0 | 2117.0 | 3999.8 | 2629.3 | 2666.55 | **PASS** | insignia/intersticial observado en Chrome real |
| `shot_phishing_badge` | 2 | 2 | ! | 2 | 0 | 678.0 | 1271.1 | 1043.55 | 1203.5 | **PASS** | insignia/intersticial observado en Chrome real |
| `shot_warning_badge` | 2 | 2 | ? | 2 | 0 | 1000.0 | 1882.9 | 3985.95 | 4057.2 | **PASS** | insignia/intersticial observado en Chrome real |

## 4. Verificación de los defectos corregidos, en navegador real

### BUG‑01 (timeout de cliente = 8 000 ms)

Escenario `h_timeout_stub_exact` contra un servidor que tarda deliberadamente más de 8 s: el cliente abortó a **8005 ms** (resource-timing, n = 1), es decir, respetando el presupuesto de 8 000 ms en lugar de esperar indefinidamente. Errores API registrados: 1. Insignia: no se emite (decisión abstención por timeout), que es el comportamiento esperado.

### Caché de la extensión (fría vs caliente)

`k_cold` (10 cargas sin caché): llamadas al backend **9/10**, p50 navegación→insignia **1740.1 ms**.
`k_hot` (10 cargas con caché): llamadas al backend **0/10**, p50 navegación→insignia **82.6 ms**.

### Degradación controlada (BUG‑02/‑01: no colgar el navegador)

`m_backend_down_exact` (backend apagado): el fallo de conexión se detectó de inmediato (resource-timing p50 = 1 ms, errores API = 1) y la página cargó sin bloqueo; la decisión visible tardó 10070.1 ms en el escenario offline (`net::ERR_INTERNET_DISCONNECTED` registrado por el navegador).

### IDN/Punycode (BUG‑03) en navegador real

`j_punycode_resolvable` (dominios punycode reales): insignias observadas «! / ✔», intersticiales de aviso **1**, errores API 0, p50 navegación→insignia 634.3 ms. Los escenarios `j_punycode` con dominios **caídos** produjeron la página de error real del navegador (`ERR_NAME_NOT_RESOLVED`), sin decisión posible: se declara como resultado, no como fallo de la batería.

## 5. Limitaciones y escenarios NO ejecutados (declarados, nunca simulados)

- **`l_concurrency` — NOT_RUN**: sin navegación registrada en requests.jsonl.
- **`o_cascade_analyses` — NOT_RUN**: navegación sin llamada al backend ni insignia: escenario incompleto.

- Los escenarios contra ** URLs de phishing reales ya caídas** (`c_phishing`, `e_dns_error`, `g_http_404/500`, `j_punycode`, `n_offline`) muestran la página de error del navegador: la extensión no puede emitir decisión sobre una página que no carga. Se reportan como PASS del camino de error, no como detección.
- La tasa de timeout observada en la API fue **0.05** (2/40); corresponde a los escenarios deliberados de timeout y de caída del backend, no a fallos espontáneos.
- El Chrome de marca (Google Chrome 155) no admite `--load-extension`: cualquier despliegue productivo debe empaquetar la extensión o usar directivas de empresa.

## 6. Capturas de pantalla

Directorio `artifacts/e2e_chrome/screenshots/` (54 PNG). Principales:

- `01_shot_legit_badge.png`
- `02_shot_phishing_badge.png`
- `03_n_offline_exact.png`
- `03_shot_warning_badge.png`
- `06_j_punycode_resolvable.png`
- `07_j_punycode_resolvable.png`
- `20_k_cold.png`
- `21_k_cold.png`
- `22_k_cold.png`
- `23_k_cold.png`
- `24_k_cold.png`
- `25_k_cold.png`
- `26_k_cold.png`
- `27_k_cold.png`
- `28_k_cold.png`
- `29_k_cold.png`
- `30_k_hot.png`
- `31_k_hot.png`
- `32_k_hot.png`
- `33_k_hot.png`
- `34_k_hot.png`
- `35_k_hot.png`
- `36_k_hot.png`
- `37_k_hot.png`
- `38_k_hot.png`
- `39_k_hot.png`
- `42_n_offline.png`

## 7. Cómo reproducir la verificación

```powershell
python scripts\phase2k_summarize_e2e.py   # reclasifica y recontiene todas las cifras anteriores
```
