# ENTREGABLE D. LIMITACIONES CIENTÍFICAS, RIESGOS TÉCNICOS Y EXPERIMENTOS PENDIENTES

**Fecha de consolidación:** 2026-10-13 UTC  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base auditado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Destino editorial:** Sección de Amenazas a la Validez (*Threats to Validity*), Limitaciones y Trabajo Futuro del artículo para *Revista Politécnica* (EPN, Scopus).

---

## 1. Amenazas a la Validez y Limitaciones Metodológicas Verificadas

### 1.1 Sesgo de Formato y Procedencia en el Corpus Maestro (`0.1.0`, $N = 176,201$)
1. **Atajo de longitud de ruta (`path_length` shortcut) en modelos de URL completa:**
   - En [`data/processed/0.1.0/samples.csv`](file:///d:/Proyects/Seguridad_Informacion/data/processed/0.1.0/samples.csv), las `99,994` muestras legítimas provienen de dominios de Tranco normalizados como URLs raíz (`https://dominio.tld/`, `path_depth = 0`), mientras que las `76,207` muestras de phishing de PhishTank conservan rutas profundas (`/login/auth.php?...`).
   - Como demostró nuestra Fase IV ([`04_COMPARACION_CIENTIFICA.md`](file:///d:/Proyects/Seguridad_Informacion/04_COMPARACION_CIENTIFICA.md)), cualquier modelo que incluya variables de ruta o n-gramas sobre la URL completa alcanza métricas internas artificialmente cercanas a la perfección (`F1 = 0.949–0.999`), pero colapsa en datos externos independientes (`ROC-AUC = 0.4749–0.6730` en $N = 1,054$).
2. **Atajo del prefijo `www.` (`subdomain_count` shortcut) en los modelos `M0–M2` congelados:**
   - Aunque PhishPe restringió acertadamente `M0` a las 11 variables de autoridad del host (`AUTHORITY_FEATURE_NAMES`), las URLs legítimas de Tranco en `samples.csv` se construyeron sin el prefijo `www.` (`subdomain_count = 0`, `host_label_count = 2`), mientras que las URLs de PhishTank incluyen frecuentemente `www.`.
   - En consecuencia, cuando `M0` congelado evalúa URLs externas legítimas que incluyen `www.` por convención institucional (como `http://www.espol.edu.ec/` en `Hipo Universities`, $n = 200$), sufre una tasa de falsos positivos del **`94.00%` (`188/200`)** (`FPR = 46.70%` global y `ROC-AUC = 0.4859` en $N = 1,054$).
   - Al aplicar la ablación sin reentrenamiento `strip_www()` ([`02b_external_forensic_www_ablation.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase2_externa/02b_external_forensic_www_ablation.json)), la FPR externa de `M0` cae de **`46.70%` a `9.69%`** y su `ROC-AUC` sube de **`0.4859` a `0.7530`** (`PR-AUC = 0.8135`), y en el subconjunto multimodal vivo ($N_{\text{CC}} = 104$) `M2` alcanza **`ROC-AUC = 0.9248` (`PR-AUC = 0.9423`, `FPR = 2.00%`)**.
   - **Declaración obligatoria en el artículo:** Debe reportarse explícitamente tanto el resultado externo crudo como el resultado tras normalización `strip_www()`, explicando que la versión `0.1.0` de [`extract_url_features()`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/features.py#L46-L86) cuenta `www.` como subdominio adicional.

### 1.2 Sesgo de Supervivencia y Disponibilidad en Evaluaciones Multimodales en Vivo (*Intention-to-Evaluate* vs. *Complete-Case*)
- Los sitios de phishing tienen una vida media operativa de pocas horas. En nuestra sonda multimodal externa en vivo ($N_{\text{ITE}} = 240$), el **`56.67%` (`136/240`)** de las URLs no completaron la extracción simultánea de infraestructura y DOM HTML (`61.67%` de atriición en phishing por caída de dominio o bloqueo TLS frente a `51.67%` en legítimas por bloqueos WAF/anti-bot o timeouts).
- De manera análoga, en la evaluación visual Chrome CDP del conjunto interno ($N = 691$), las `83` muestras con captura CDP exitosa presentan un sesgo positivo de disponibilidad de `+1.39` a `+4.67` puntos de F1 en `M0–M2` respecto a las `608` muestras sin captura CDP ([`06_VISUAL_Y_LLM.md`](file:///d:/Proyects/Seguridad_Informacion/06_VISUAL_Y_LLM.md)).
- Por tanto, las métricas *complete-case* de `M1–M5` representan el rendimiento **condicionado a que el servidor remoto sea accesible en tiempo real**, mientras que para dominios caídos o inaccesibles el sistema debe degradarse graciosamente al clasificador léxico `M0` / `HybridM0Model`.

### 1.3 Dependencia de Prevalencia Operativa y Listas de Reputación (`Tranco Top-1M`)
- En un escenario de navegación real donde la prevalencia de phishing es baja ($\pi \in [0.1\%, 1.0\%]$), un clasificador con `FPR = 3.20%` (`M0` puro) genera `320` falsas alarmas por cada `10,000` sitios legítimos, hundiendo el Valor Predictivo Positivo (`PPV`). Solo los puntos de operación con `FPR <= 0.40%` (`M2`, `M4` calibrado o `HybridM0Model` en umbral conservador) mantienen una carga de alertas operativamente tolerable.
- Asimismo, aunque `HybridM0Model` mantiene una discriminación sólida sin Tranco (`ROC-AUC = 0.7710`, `FPR = 2.20%` en datos externos), su `ROC-AUC = 0.9963` interno depende de la presencia de dominios benignos en la lista Tranco Top-1M, lo cual no protege frente a ataques alojados en subdominios gratuitos de plataformas incluidas en Tranco si no se aplican reglas específicas de *free-hosting*.

---

## 2. Hallazgos de Auditoría de Software y Riesgos Técnicos en el Código Actual

Nuestra auditoría de código e integración en la Fase III ([`03_EXTENSION_REAL.md`](file:///d:/Proyects/Seguridad_Informacion/03_EXTENSION_REAL.md)) identificó **seis defectos de ingeniería verificables** que deben documentarse como limitaciones técnicas del prototipo actual:

| ID | Componente y Ubicación Exacta | Defecto Técnico Verificado | Impacto Medido en Validación |
|---|---|---|---|
| **Bug 1** | [`extension/background.js`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js#L35) vs. [`detection_rules.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/detection_rules.py#L728-L809) | El cliente aborta `POST /check` a los **`6,000 ms`**, pero el backend lanza hilos WHOIS/GeoIP con timeout de **`8,000 ms`**. | En caché fría ($N=20$), $P_{99} = 9,520.85\text{ ms}$ y el **`5.0%` de las peticiones aborta por timeout**, dejando al navegador sin protección (*fail-open*). |
| **Bug 2** | [`src/phishguard_infra/policy.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/policy.py#L78) llamado desde [`main.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_api/main.py#L194) | `validate_url_ssrf_safety()` ejecuta `socket.getaddrinfo()` **síncrono y bloqueante** dentro del *event loop* asíncrono de FastAPI. | Bloquea la concurrencia del worker ASGI cuando un dominio malicioso tiene resolución DNS lenta o inexistente. |
| **Bug 3** | [`homoglyphs.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/homoglyphs.py#L106) vs. [`hybrid_m0.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/hybrid_m0.py#L163) y [`background.js`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js#L140) | `analyze_homoglyphs()` devuelve `"homoglyph_brand_spoofing_detected"`, pero `HybridM0Model` y la extensión leen `"is_spoofing"`. Además, `to_visual_skeleton()` no decodifica Punycode `xn--`. | **Código muerto:** El override de homógrafos nunca se activa. `https://www.xn--pple-43d.com/login` (`аpple.com` cirílico) recibe `decision: "legitimate"`, `prob = 0.0935`. |
| **Bug 4** | [`src/phishguard_ml/cascade/engine.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/cascade/engine.py#L102-L133) | `decide_next()` usa un único `uncertainty_threshold = 0.20` tanto para parada temprana como para abstención final (en vez de `0.15` calibrado). | En $N=691$, duplica la abstención (`8.54%` vs. `4.20%`) y eleva la FPR de `0.20%` (`M4`) a `4.00%` (`F1 = 0.9010`). |
| **Bug 5** | [`src/phishguard_infra/worker.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/worker.py#L154-L162) | Si `m0_prob >= 0.50`, fuerza `action = "visual"` saltándose `M1` y `M2`, e invoca `predict_m3()` con diccionarios vacíos `{}` para infraestructura y DOM. | Evalúa `M3` con `39/82` variables en cero artificial, degradando la precisión al `81.82%` en esas muestras. |
| **Bug 6** | [`src/phishguard_infra/worker.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/worker.py#L243-L249) | Si el LLM responde con `llm_prob > 0`, sobrescribe incondicionalmente `final_prob = llm_prob` y descarta la predicción de `M2`. | Un LLM pequeño descalibrado (`F1 = 0.0000` en $\tau=0.50$ en `benchmark_summary.json`) anula las garantías de calibración y FPR de la cascada. |

---

## 3. Riesgos Operativos de la Cascada y de la Abstención Selectiva (`M4` / `M5`)

1. **Riesgo de salida temprana benigna en `M0` (`12` de los `15` falsos negativos silenciosos de `M5`):**
   - En [`05_CASCADA_ABLACIONES.md`](file:///d:/Proyects/Seguridad_Informacion/05_CASCADA_ABLACIONES.md) demostramos que sobre el mismo subconjunto decidido ($N = 662$), `M2` monolítico (`F1 = 0.9636`, `11` FN) supera numéricamente a `M5_selective` (`F1 = 0.9538`, `15` FN) porque **`12` URLs de phishing alojadas en dominios comprometidos o plataformas benignas salen prematuramente en `M0`** con probabilidad muy baja ($\bar{p}_{M0} = 0.0106, \mathcal{H} \le 0.15$) sin que se inspeccione su infraestructura ni su HTML.
   - Nuestra política alternativa **`Conservative Cascade (Mandatory M1 for Benign)`** corrige este fallo estructural y eleva el F1 global en $N=691$ de `0.9248` (`M4`) a **`0.9341`**, pero aún no está desplegada por defecto en producción.
2. **Vulnerabilidad ante acortadores de URL y redirecciones (`url_shortener_simulator`):**
   - En la evaluación adversarial ($N = 191$ phishing), los ataques mediante acortadores de URL alcanzan una tasa de éxito (`ASR`) del **`100.0%`** en `M0–M4` y una evasión silenciosa del **`99.48%` (`190/191`)** en `M5`, ya que el dominio del acortador (`bit.ly`, `tinyurl.com`) es léxicamente legítimo si no se resuelve previamente la cadena HTTP `301/302` antes de `M0`.

---

## 4. Experimentos y Desarrollos Clasificados como Pendientes para Trabajo Futuro

De acuerdo con el Principio Científico 10 del protocolo, ningún experimento limitado por cuotas externas o alcance arquitectónico fue simulado ni extrapolado. Se registran como **pendientes verificados**:

| ID | Experimento / Mejora Pendiente | Causa Documentada de Estado Pendiente | Trabajo Necesario para Completarlo |
|---|---|---|---|
| **P1** | **Evaluación completa del LLM en vivo sobre las `20` muestras restantes abstenidas por `M5` ($9/29$ completadas)** | Límite estricto de *Tokens Per Minute* (`HTTP 429 RateLimitError`, 6,000–8,000 TPM) en el tier gratuito de la API de Groq para `openai/gpt-oss-20b`. | Ejecutar [`scripts/evaluate_llm_on_m5_abstained_live.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/evaluate_llm_on_m5_abstained_live.py) con una clave API de nivel de pago (*Pay-as-you-go*) o con pausas de `65 s` entre llamadas para completar las `20` muestras restantes (`14` phishing y `6` legítimas) y estrechar el IC 95% actual (`[0.5455, 1.0000]`). |
| **P2** | **Reentrenamiento v0.2.0 de `M0–M5` con normalización canónica `strip_www()` y muestreo de rutas benignas profundas** | El protocolo de validación externa (Sección 5.3) exigió **congelar estrictamente los modelos existentes** sin reentrenarlos durante la prueba principal. | Incorporar `strip_www()` dentro de [`extract_url_features()`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/features.py) y recolectar URLs legítimas con rutas internas (mediante rastreo controlado de enlaces internos) antes de reentrenar la familia `M0–M5`. |
| **P3** | **Sustitución de las 32 características visuales estadísticas (`Visual_Only` `ROC-AUC = 0.5584`) por detección semántica de logotipos** | Los descriptores actuales en [`src/phishguard_ml/visual.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/visual.py) se basan en histogramas de luminancia, bordes y `pHash` de pantalla completa, que no discriminan logotipos incrustados (`ROC-AUC = 0.5584` en $N=83$ CDP). | Integrar un detector ligero de regiones de logotipos e identidad visual (p. ej., `YOLOv8n-logo` + embeddings `CLIP`/`SigLIP` comparados contra la base de marcas de `configs/brand-country-map.json`) y filtrar capturas CDP en blanco (`luminance_std < 1.0`) esperando al evento `networkIdle`. |
| **P4** | **Corrección en rama de producción de los 6 defectos de software (Bugs 1–6) e integración nativa de la Configuración C** | Para no alterar silenciosamente el comportamiento base auditado de la extensión (Sección 6), las correcciones y la Configuración C (`HybridM0 -> M1 -> M2/M5`) se evaluaron sin sobrescribir la ruta de producción. | Aplicar el parche de 5 líneas en `homoglyphs.py` / `hybrid_m0.py` (`idna.decode` + clave `"homoglyph_brand_spoofing_detected"`), envolver `socket.getaddrinfo` en `asyncio.to_thread()`, alinear el timeout a `3,500 ms` y exponer la Configuración C como modo seleccionable en `extension/popup.js`. |
