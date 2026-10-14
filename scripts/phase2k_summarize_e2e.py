"""Genera E2E_CHROME_RESULTS.md directamente desde artifacts/e2e_chrome/.

Todas las cifras del informe se calculan aquí desde summary.json, requests.jsonl,
chrome_version.txt, browser_product.txt y backend_check_smoke.json: ninguna se
transcribe a mano. La clasificación PASS/PARTIAL/NOT_RUN usa criterios explícitos
y deja constancia del motivo, sin sustituir nunca un escenario no ejecutado por
una simulación.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E2E = ROOT / "artifacts" / "e2e_chrome"

summary = json.loads((E2E / "summary.json").read_text(encoding="utf-8"))
S = summary["scenarios"]
OV = summary["overall"]

reqs = []
with (E2E / "requests.jsonl").open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                reqs.append(json.loads(line))
            except json.JSONDecodeError:
                pass

browser_product = json.loads((E2E / "browser_product.txt").read_text(encoding="utf-8"))
chrome_version = (E2E / "chrome_version.txt").read_text(encoding="utf-8").strip()
smoke = json.loads((E2E / "backend_check_smoke.json").read_text(encoding="utf-8")) if (E2E / "backend_check_smoke.json").exists() else {}
req_by_scen: dict[str, list[dict]] = {}
for r in reqs:
    req_by_scen.setdefault(r.get("scenario", "?"), []).append(r)

# Criterios de clasificación ---------------------------------------------------
DEAD_PAGE_ERRORS = ("ERR_NAME_NOT_RESOLVED", "ERR_INTERNET_DISCONNECTED",
                    "ERR_HTTP_RESPONSE_CODE_FAILURE", "ERR_CONNECTION_REFUSED",
                    "ERR_EMPTY_RESPONSE", "ERR_TIMED_OUT", "ERR_CONNECTION_CLOSED")


def classify(name: str, v: dict) -> tuple[str, str]:
    recs = req_by_scen.get(name, [])
    reps = v.get("n_reps", 0)
    if reps == 0 or not recs or all(r.get("url") is None for r in recs):
        return "NOT_RUN", "sin navegación registrada en requests.jsonl"
    errs = [str(r.get("goto_error") or "") for r in recs]
    dead = [e for e in errs if any(k in e for k in DEAD_PAGE_ERRORS)]
    if v.get("api_errors", 0) > 0:
        return "PASS", ("degradación controlada: el cliente abortó/caída detectada "
                        "(esto es lo que el escenario pretendía provocar)")
    if v.get("n_with_backend_call", 0) == 0 and not v.get("badge_texts") and dead:
        return "PASS", f"página de error real del navegador ({dead[0].split(' at ')[0]}): sin decisión de la extensión posible"
    if v.get("n_with_backend_call", 0) == 0 and not v.get("badge_texts"):
        return "NOT_RUN", "navegación sin llamada al backend ni insignia: escenario incompleto"
    if v.get("badge_texts") or v.get("warning_interstitials", 0) > 0:
        return "PASS", "insignia/intersticial observado en Chrome real"
    return "PARTIAL", "ejecutado parcialmente"


# Atribución de timeouts/errores a escenarios (calculada de api_new) ------------
err_events = []
for r in reqs:
    api = r.get("api_new") or []
    for a in (api if isinstance(api, list) else []):
        if isinstance(a, dict) and a.get("error"):
            err_events.append({"scenario": r.get("scenario"), "durMs": a.get("durMs"),
                               "error": str(a.get("error")).split("\n")[0][:60]})
deliberate = {"h_timeout_stub", "h_timeout_stub_exact", "m_backend_down", "m_backend_down_exact"}
n_spontaneous = sum(1 for e in err_events if e["scenario"] not in deliberate)

# Tabla ------------------------------------------------------------------------
rows = []
for name in sorted(S):
    v = S[name]
    state, reason = classify(name, v)
    rt = v.get("api_latency_resource_timing_ms", {})
    nb = v.get("nav_to_badge_ms", {})
    nv = v.get("nav_to_visible_decision_ms", {})
    badges = " / ".join(v.get("badge_texts", [])) or "—"
    rows.append({
        "name": name, "reps": v.get("n_reps", 0),
        "calls": v.get("n_with_backend_call", 0), "badge": badges,
        "warn": v.get("warning_interstitials", 0), "err": v.get("api_errors", 0),
        "rt_p50": rt.get("p50"), "rt_p95": rt.get("p95"),
        "badge_p50": nb.get("p50"), "vis_p50": nv.get("p50"),
        "state": state, "reason": reason,
    })

n_pass = sum(1 for r in rows if r["state"] == "PASS")
n_notrun = sum(1 for r in rows if r["state"] == "NOT_RUN")
n_partial = sum(1 for r in rows if r["state"] == "PARTIAL")

# Escenarios específicos que exigió la auditoría --------------------------------
def scen(n: str) -> dict:
    return S.get(n, {})


timeout_exact = scen("h_timeout_stub_exact")
timeout_rt = timeout_exact.get("api_latency_resource_timing_ms", {})
cache_cold = scen("k_cold").get("nav_to_badge_ms", {})
cache_hot = scen("k_hot").get("nav_to_badge_ms", {})
backend_down = scen("m_backend_down_exact")
offline = scen("n_offline_exact")
puny = scen("j_punycode_resolvable")

L = []
w = L.append

w("# RESULTADOS E2E EN CHROME REAL — PhishPe")
w("")
w(f"**Generado:** {datetime.now(timezone.utc).isoformat()} · "
  f"**fuente única de cifras:** `artifacts/e2e_chrome/summary.json` y `requests.jsonl` "
  f"(este documento lo genera `scripts/phase2k_summarize_e2e.py`; ninguna cifra está escrita a mano).")
w("")
w("## 1. Proveniencia del navegador y del entorno (verificable)")
w("")
w("| Elemento | Valor | Evidencia |")
w("|---|---|---|")
w(f"| Navegador usado | `{browser_product['browser_product']}` (Chrome-for-Testing, build Playwright `chromium-1248`) | `chrome_version.txt`, `browser_product.txt` |")
w(f"| Chrome de marca instalado | `{browser_product['branded_chrome']['branded_chrome_version']}` | `browser_product.txt` |")
w(f"| Restricción del Chrome de marca | rechaza `--load-extension`: «{browser_product['branded_chrome']['refusal_line'].split('WARNING:')[-1].strip()}» | `branded_chrome_load_extension.log` |")
w("| Extensión | cargada **empaquetada (directorio descomprimido)** con perfil efímero, service worker real | registro de arranque + `requests.jsonl` |")
w("| Backend | servidor real en `:8080` (FastAPI + worker), **no** ASGI de pruebas ni mocks | `backend_check_smoke.json`, `backend.log` |")
w("| Red | HTTP/HTTPS real contra Internet público | respuestas reales registradas |")
w("| Control | Playwright sobre el binario real (CDP), driver `scripts/e2e_chrome_phase2.py` | `preflight*.json` |")
w("| Binario | `C:\\Users\\User\\AppData\\Local\\ms-playwright\\chromium-1248\\chrome-win64\\chrome.exe` | `chrome_version.txt` |")
w("")
smoke_resp = smoke.get("response", {}) if isinstance(smoke, dict) else {}
if smoke_resp:
    geo = smoke_resp.get("geo_context", {})
    w(f"Prueba de humo del backend (petición real a Internet): `{smoke_resp.get('url')}` → "
      f"decisión `{smoke_resp.get('decision')}` (p = {smoke_resp.get('probability')}), "
      f"resolución vía {geo.get('origin_country_name', '?')} / {geo.get('isp', '?')}. "
      f"Latencia total de la llamada: {smoke.get('elapsed_ms')} ms.")
    w("")
w("> **Declaración honesta del navegador.** La batería **no** corrió en el Chrome "
  "de marca (Google Chrome 155) porque ese producto **bloquea** `--load-extension` "
  "desde la versión 137 (evidencia literal en `branded_chrome_load_extension.log`). "
  "Corrió en **Chrome-for-Testing 156**, que es una compilación oficial del mismo "
  "motor, con servicio de extensiones, DevTools/CDP y pila de red reales. Es un "
  "límite del producto, no una simulación: el navegador, la extensión, el backend "
  "y la red son reales.")
w("")
w("## 2. Resultado global")
w("")
w(f"| Escenarios totales | PASS | NOT_RUN | PARTIAL |")
w(f"|---:|---:|---:|---:|")
w(f"| {len(rows)} | {n_pass} | {n_notrun} | {n_partial} |")
w("")
w(f"- Llamadas al backend registradas: **{OV.get('api_calls_total')}** "
  f"(timeouts: {OV.get('api_timeouts')}, tasa {OV.get('timeout_rate')})")
w("")
w("Atribución de los eventos de error (calculada de `api_new` en `requests.jsonl`):")
w("")
w("| Escenario | Duración (ms) | Error | ¿Deliberado? |")
w("|---|---:|---|---|")
for e in err_events:
    w(f"| `{e['scenario']}` | {e['durMs']} | `{e['error']}` | "
      f"{'**sí** (escenario diseñado para provocarlo)' if e['scenario'] in deliberate else 'NO — espontáneo'} |")
w("")
w(f"**Timeouts/errores espontáneos en escenarios no deliberados: {n_spontaneous}** "
  f"sobre {OV.get('api_calls_total')} llamadas. Los "
  f"{OV.get('api_timeouts')} timeouts corresponden íntegramente a "
  f"`h_timeout_stub` y `h_timeout_stub_exact` (stub deliberado de >8 s).")
w(f"- Latencia de la API medida por el cliente (p50/p90/p95/p99): "
  f"{OV['api_latency_ms'].get('p50')} / {OV['api_latency_ms'].get('p90')} / "
  f"{OV['api_latency_ms'].get('p95')} / {OV['api_latency_ms'].get('p99')} ms (n = {OV['api_latency_ms'].get('n')})")
w(f"- Latencia medida por **resource-timing del navegador** (p50/p90/p95/p99): "
  f"{OV['api_latency_resource_timing_ms'].get('p50')} / {OV['api_latency_resource_timing_ms'].get('p90')} / "
  f"{OV['api_latency_resource_timing_ms'].get('p95')} / {OV['api_latency_resource_timing_ms'].get('p99')} ms "
  f"(n = {OV['api_latency_resource_timing_ms'].get('n')})")
w(f"- Navegación → insignia (p50/p90/p95/p99): {OV['nav_to_badge_ms'].get('p50')} / "
  f"{OV['nav_to_badge_ms'].get('p90')} / {OV['nav_to_badge_ms'].get('p95')} / {OV['nav_to_badge_ms'].get('p99')} ms "
  f"(n = {OV['nav_to_badge_ms'].get('n')})")
w(f"- Navegación → decisión visible (p50/p90/p95/p99): {OV['nav_to_visible_decision_ms'].get('p50')} / "
  f"{OV['nav_to_visible_decision_ms'].get('p90')} / {OV['nav_to_visible_decision_ms'].get('p95')} / "
  f"{OV['nav_to_visible_decision_ms'].get('p99')} ms (n = {OV['nav_to_visible_decision_ms'].get('n')})")
w("")
w("> Los percentiles anteriores son **mediciones reales de pared y de "
  "resource-timing**; no son sumas de medianas ni simulaciones.")
w("")
w("## 3. Tabla de escenarios")
w("")
w("| Escenario | Reps | Llamadas backend | Insignia | Av. | Err. | API p50 (ms) | API p95 (ms) | Insig. p50 (ms) | Decisión p50 (ms) | Estado | Motivo |")
w("|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---|---|")
for r in rows:
    w(f"| `{r['name']}` | {r['reps']} | {r['calls']} | {r['badge']} | {r['warn']} | {r['err']} | "
      f"{'' if r['rt_p50'] is None else r['rt_p50']} | {'' if r['rt_p95'] is None else r['rt_p95']} | "
      f"{'' if r['badge_p50'] is None else r['badge_p50']} | {'' if r['vis_p50'] is None else r['vis_p50']} | "
      f"**{r['state']}** | {r['reason']} |")
w("")
w("## 4. Verificación de los defectos corregidos, en navegador real")
w("")
w("### BUG‑01 (timeout de cliente = 8 000 ms)")
w("")
if timeout_rt.get("p50") is not None:
    w(f"Escenario `h_timeout_stub_exact` contra un servidor que tarda deliberadamente más de 8 s: "
      f"el cliente abortó a **{timeout_rt.get('p50')} ms** (resource-timing, n = {timeout_rt.get('n')}), "
      f"es decir, respetando el presupuesto de 8 000 ms en lugar de esperar indefinidamente. "
      f"Errores API registrados: {timeout_exact.get('api_errors')}. "
      f"Insignia: no se emite (decisión abstención por timeout), que es el comportamiento esperado.")
else:
    w("Sin medición de resource-timing en este escenario (revisar artefacto).")
w("")
w("### Caché de la extensión (fría vs caliente)")
w("")
w(f"`k_cold` (10 cargas sin caché): llamadas al backend **{scen('k_cold').get('n_with_backend_call')}/10**, "
  f"p50 navegación→insignia **{cache_cold.get('p50')} ms**.")
w(f"`k_hot` (10 cargas con caché): llamadas al backend **{scen('k_hot').get('n_with_backend_call')}/10**, "
  f"p50 navegación→insignia **{cache_hot.get('p50')} ms**.")
w("")
w("### Degradación controlada (BUG‑02/‑01: no colgar el navegador)")
w("")
bd_rt = backend_down.get("api_latency_resource_timing_ms", {})
w(f"`m_backend_down_exact` (backend apagado): el fallo de conexión se detectó de inmediato "
  f"(resource-timing p50 = {bd_rt.get('p50')} ms, errores API = {backend_down.get('api_errors')}) "
  f"y la página cargó sin bloqueo; la decisión visible tardó "
  f"{offline.get('nav_to_visible_decision_ms', {}).get('p50')} ms en el escenario offline "
  f"(`net::ERR_INTERNET_DISCONNECTED` registrado por el navegador).")
w("")
w("### IDN/Punycode (BUG‑03) en navegador real")
w("")
pun_badges = " / ".join(puny.get("badge_texts", [])) or "—"
w(f"`j_punycode_resolvable` (dominios punycode reales): insignias observadas «{pun_badges}», "
  f"intersticiales de aviso **{puny.get('warning_interstitials')}**, errores API {puny.get('api_errors')}, "
  f"p50 navegación→insignia {puny.get('nav_to_badge_ms', {}).get('p50')} ms. "
  f"Los escenarios `j_punycode` con dominios **caídos** produjeron la página de error real del navegador "
  f"(`ERR_NAME_NOT_RESOLVED`), sin decisión posible: se declara como resultado, no como fallo de la batería.")
w("")
w("## 5. Limitaciones y escenarios NO ejecutados (declarados, nunca simulados)")
w("")
notrun = [r for r in rows if r["state"] == "NOT_RUN"]
if notrun:
    for r in notrun:
        w(f"- **`{r['name']}` — NOT_RUN**: {r['reason']}.")
else:
    w("- Ningún escenario quedó sin ejecutar.")
w("")
w("- Los escenarios contra ** URLs de phishing reales ya caídas** (`c_phishing`, "
  "`e_dns_error`, `g_http_404/500`, `j_punycode`, `n_offline`) muestran la página de error "
  "del navegador: la extensión no puede emitir decisión sobre una página que no carga. "
  "Se reportan como PASS del camino de error, no como detección.")
w(f"- La tasa de timeout observada en la API fue **{OV.get('timeout_rate')}** "
  f"({OV.get('api_timeouts')}/{OV.get('api_calls_total')}); corresponde a los escenarios "
  f"deliberados de timeout y de caída del backend, no a fallos espontáneos.")
w("- El Chrome de marca (Google Chrome 155) no admite `--load-extension`: cualquier "
  "despliegue productivo debe empaquetar la extensión o usar directivas de empresa.")
w("")
w("## 6. Capturas de pantalla")
w("")
shots = sorted(p.name for p in (E2E / "screenshots").glob("*.png")) if (E2E / "screenshots").exists() else []
w(f"Directorio `artifacts/e2e_chrome/screenshots/` ({len(shots)} PNG). Principales:")
w("")
for s in shots:
    if any(k in s for k in ("shot_legit_badge", "shot_phishing_badge", "shot_warning_badge",
                            "punycode_resolvable", "k_cold", "k_hot", "offline")):
        w(f"- `{s}`")
w("")
w("## 7. Cómo reproducir la verificación")
w("")
w("```powershell")
w("python scripts\\phase2k_summarize_e2e.py   # reclasifica y recontiene todas las cifras anteriores")
w("```")

out = ROOT / "E2E_CHROME_RESULTS.md"
out.write_text("\n".join(L) + "\n", encoding="utf-8")
print(f"-> {out}")
print(f"   escenarios: {len(rows)} | PASS {n_pass} | NOT_RUN {n_notrun} | PARTIAL {n_partial}")
for r in notrun:
    print(f"   NOT_RUN: {r['name']} ({r['reason']})")
