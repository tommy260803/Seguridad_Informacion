# FASE VI. EVALUACIÓN RIGUROSA DE LOS COMPONENTES VISUAL (CHROME CDP) Y LLM (GROQ)

**Fecha de ejecución:** 2026-10-13 UTC  
**Rama experimental:** `experimental/validacion-scopus-fase2`  
**Commit base auditado:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`  
**Semilla aleatoria global:** `SEED = 42` (`B = 2,000` réplicas bootstrap)  
**Artefacto primario verificable:** [`06_visual_y_llm_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase6_visual_llm/06_visual_y_llm_results.json)  
**Script de generación reproducible:** [`scripts/fase2_06_visual_y_llm.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/fase2_06_visual_y_llm.py)

---

## PARTE I. COMPONENTE VISUAL (`M3`, Secciones 9.1 y 9.2)

### 1.1 Auditoría Forense de los Artefactos Visuales (`visual-results-real.jsonl` vs. `visual-results-authentic-cdp.jsonl`)

El repositorio contiene dos archivos de resultados visuales cuya naturaleza y alcance deben distinguirse con absoluta claridad en el manuscrito:

1. **[`artifacts/analysis-results/visual-results-real.jsonl`](file:///d:/Proyects/Seguridad_Informacion/artifacts/analysis-results/visual-results-real.jsonl) ($N = 10,000$ registros):**
   - Contiene `5,612` registros con `status = "success"`, pero de ellos **`4,949` (`88.19%`) tienen `visual_observation_available = 0.0`** (vectores de ceros porque no se ejecutó renderizado gráfico sobre el corpus completo) y solo **`663` (`11.81%`) tienen `visual_observation_available = 1.0`**.
   - Además, como documentó la auditoría forense previa, las `91` imágenes PNG en [`artifacts/screenshots/`](file:///d:/Proyects/Seguridad_Informacion/artifacts/screenshots) fueron generadas por un renderizador sintético sobre lienzo blanco (`PIL.ImageDraw`, `mean_luminance > 0.99`). **Por principio científico estricto, estas imágenes no son capturas de navegador y nunca deben presentarse como tales.**
2. **[`artifacts/analysis-results/visual-results-authentic-cdp.jsonl`](file:///d:/Proyects/Seguridad_Informacion/artifacts/analysis-results/visual-results-authentic-cdp.jsonl) ($N = 10,000$ registros, `616` intentos reales con Chrome CDP):**
   - Generado mediante [`scripts/capture_authentic_cdp_visual.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/capture_authentic_cdp_visual.py) invocando Google Chrome real (`chrome.exe --headless=new`) conectado por WebSocket al *Chrome DevTools Protocol* (`Page.navigate` + `Page.captureScreenshot`).
   - La Tabla 1 detalla la contabilidad exacta de los `10,000` registros y el desglose por partición y clase de los `616` intentos reales.

| Estado en `visual-results-authentic-cdp.jsonl` | `capture_mode` | `error_code` | Total | `train` (Phish / Legit) | `validation` (Phish / Legit) | `test` (Phish / Legit) |
|---|---|---|---:|---:|---:|---:|
| **Intentadas con Chrome CDP en vivo** | `live_cdp` / `live_cdp_failed` | — | **`616`** | **`342` (`174` / `168`)** | **`105` (`51` / `54`)** | **`169` (`83` / `86`)** |
| ├─ **Captura auténtica exitosa** | `live_cdp` | `None` | **`467` (`75.81%`)** | **`313` (`163` / `150`)** | **`71` (`37` / `34`)** | **`83` (`28` / `55`)** |
| ├─ Fallo por timeout de navegación | `live_cdp_failed` | `timeout` | `131` (`21.27%`) | `29` (`11` / `18`) | `34` (`14` / `20`) | `68` (`42` / `26`) |
| ├─ Fallo por timeout de socket CDP | `live_cdp_failed` | `live_timeout` | `12` (`1.95%`) | `0` | `0` | `12` (`8` / `4`) |
| └─ Fallo por captura vacía | `live_cdp_failed` | `empty_shot` | `6` (`0.97%`) | `0` | `0` | `6` (`5` / `1`) |
| **No intentadas (fuera de cuota de tiempo)** | `none` | `None` | `9,384` | — | — | — |

- **Latencia real medida de captura Chrome CDP ($N = 467$ capturas exitosas):**
  - $\text{Media} = 2,251.73\text{ ms}$ ($\text{DE} = 762.35\text{ ms}$), **$P_{50} = 2,204.78\text{ ms}$**, $P_{90} = 3,349.66\text{ ms}$, **$P_{95} = 3,500.16\text{ ms}$**, $P_{99} = 3,783.74\text{ ms}$.
  - Este costo temporal ($\sim 2.2\text{ s}$ por URL, más de $40\times$ la latencia mediana de `POST /check` en la extensión) demuestra empíricamente que el renderizado completo de navegador no puede ejecutarse de forma síncrona en la ruta crítica del cliente, sino únicamente de forma asíncrona sobre la fracción abstenida o dudosa.
- **Inspección física de los `40` archivos PNG retenidos en [`artifacts/authentic-cdp-screenshots/`](file:///d:/Proyects/Seguridad_Informacion/artifacts/authentic-cdp-screenshots):**
  - Todos tienen resolución nativa de viewport `1264 × 625` píxeles y tamaño entre `3,695` y `39,728` bytes (media `14,008.6` bytes, desviación estándar media de luminancia `21.97`).
  - **Hallazgo técnico importante:** `11` de los `40` PNG retenidos (`27.5%`) tienen desviación estándar de luminancia `< 1.0` (`visual_luminance_std = 0.0`, `visual_dark_pixel_ratio = 1.0`, tamaño `3,695–3,696` bytes). Corresponden a páginas SPA o protegidas por anti-bots donde `Page.captureScreenshot` capturó el fondo oscuro inicial de Chrome antes del hidratado de JavaScript. Esta observación explica parte del ruido en las características visuales estadísticas.

---

### 1.2 Análisis de Sesgo de Disponibilidad Visual ($N = 83$ con CDP vs. $N = 608$ sin CDP)

Dentro del conjunto de prueba complete-case ($N = 691$), `83` muestras cuentan con captura CDP exitosa (`28` phishing [`33.73%`] y `55` legítimas [`66.27%`]), mientras que `608` no tienen captura CDP (`163` phishing [`26.81%`] y `445` legítimas [`73.19%`]). Para verificar si las páginas donde Chrome CDP tiene éxito son intrínsecamente más fáciles o difíciles de clasificar, evaluamos los modelos **no visuales** (`M0`, `M1`, `M2`) en ambos subconjuntos por separado (Tabla 2).

| Modelo | F1 en $N = 83$ (con CDP) | F1 en $N = 608$ (sin CDP) | Diferencia $\Delta\text{F1}$ (Sesgo de Disponibilidad) | ROC-AUC en $N = 83$ | ROC-AUC en $N = 608$ | Diagnóstico |
|---|---:|---:|---:|---:|---:|---|
| **`M0` (Solo URL Autoridad)** | `0.9057 [0.8077, 0.9796]` | `0.8590 [0.8132, 0.8981]` | **`+0.0467`** | `0.9377` | `0.9053` | Las muestras con CDP activo tienen señales léxicas más claras. |
| **`M1` (URL + Infraestructura)** | `0.9434 [0.8627, 1.0000]` | `0.9221 [0.8875, 0.9514]` | **`+0.0213`** | `0.9942` | `0.9734` | `M1` ya alcanza `Precision = 100%` y `ROC-AUC = 0.9942` en $N=83$. |
| **`M2` (URL + Infra + DOM)** | `0.9434 [0.8627, 1.0000]` | `0.9295 [0.8984, 0.9563]` | **`+0.0139`** | `0.9929` | `0.9854` | Techo pre-visual altísimo (`25/28` TP, `55/55` TN) en $N=83$. |

> **Conclusión sobre sesgo de disponibilidad:** Existe un sesgo positivo de disponibilidad de `+1.39` a `+4.67` puntos porcentuales de F1: los sitios de phishing que siguen activos y responden rápidamente a Chrome CDP ($N=83$) son más fácilmente detectables por `M0–M2` (`ROC-AUC = 0.9929` en `M2`) que aquellos que ya habían caído o expirado por timeout ($N=608$). Por ello, nunca se debe comparar un modelo visual evaluado en $N=83$ contra un modelo no visual evaluado en $N=691$.

---

### 1.3 Evaluación Controlada sobre el Mismo Denominador ($N = 83$) y Señal Visual Pura (`Visual_Only_32feat`)

La Tabla 3 compara todos los modelos sobre exactamente las mismas $N = 83$ muestras de prueba con captura CDP auténtica, incluyendo un clasificador entrenado **únicamente con las 32 características visuales** (`Visual_Only_32feat`, entrenado sobre las $N = 313$ muestras de `train` con CDP auténtico) para aislar la capacidad discriminativa intrínseca del vector visual.

| Modelo Evaluado en $N = 83$ (Idéntico Denominador) | Variables Utilizadas | $\tau^*$ | TP | FP | TN | FN | Precision | Recall | F1 (IC 95% Bootstrap) | FPR | ROC-AUC (IC 95%) | PR-AUC | Brier |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---|---:|---:|
| **`Visual_Only_32feat` (Señal Visual Pura)** | **Solo 32 vars visuales CDP** | `0.2492` | `28` | `55` | `0` | `0` | `0.3373` | `1.0000` | `0.5045 [0.3725, 0.6167]` | `1.0000` | **`0.5584 [0.4739, 0.6492]`** | `0.4436` | `0.2189` |
| **`M0` (Solo URL Autoridad)** | 11 vars URL | `0.3827` | `24` | `1` | `54` | `4` | `0.9600` | `0.8571` | `0.9057 [0.8077, 0.9796]` | `0.0182` | `0.9377 [0.8652, 0.9872]` | `0.9326` | `0.0583` |
| **`M1` (URL + Infraestructura)** | 34 vars (URL+Infra) | `0.5250` | `25` | `0` | `55` | `3` | `1.0000` | `0.8929` | **`0.9434 [0.8627, 1.0000]`** | `0.0000` | **`0.9942 [0.9818, 1.0000]`** | `0.9896` | `0.0330` |
| **`M2` (URL + Infra + DOM)** | 50 vars (URL+Infra+DOM) | `0.3950` | `25` | `0` | `55` | `3` | `1.0000` | `0.8929` | **`0.9434 [0.8627, 1.0000]`** | `0.0000` | `0.9929 [0.9786, 1.0000]` | `0.9876` | `0.0363` |
| **`M3_global` (`m3-real`, predicción oficial)** | 82 vars (entrenado en $N=4,219$) | `0.3917` | `24` | `0` | `55` | `4` | `1.0000` | `0.8571` | `0.9231 [0.8333, 0.9825]` | `0.0000` | `0.9890 [0.9669, 1.0000]` | `0.9837` | `0.0331` |
| **`M3_authentic_cdp` (entrenado en $N=312$ CDP)** | 82 vars (`100%` CDP real) | `0.5000` | `26` | `4` | `51` | `2` | `0.8667` | `0.9286` | `0.8966 [0.8000, 0.9688]` | `0.0727` | `0.9789 [0.9454, 1.0000]` | `0.9623` | `0.0517` |
| **`Blend 75% M2 + 25% M3_CDP` (Exploratorio)** | Ensamble tardío de probabilidades | `0.4000` | `25` | `0` | `55` | `3` | `1.0000` | `0.8929` | `0.9434 [0.8627, 1.0000]` | `0.0000` | `0.9896 [0.9696, 1.0000]` | `0.9840` | `0.0331` |

#### Diagnóstico Científico de por qué `M3` no supera a `M2`

1. **Debilidad intrínseca de las 32 características visuales estadísticas (`Visual_Only_32feat` `ROC-AUC = 0.5584`):** Las variables con mayor importancia en `Visual_Only_32feat` son estadísticas globales de píxeles: `visual_dark_pixel_ratio` (`24.34%`), `visual_luminance_std` (`16.85%`), `visual_edge_density` (`15.53%`) y `visual_mean_luminance` (`14.26%`), mientras que la similitud de marca por pHash/HSV (`visual_brand_similarity`, `8.18%`; `visual_phash_distance_min`, `3.71%`) tiene un peso marginal porque el hashing perceptual de página completa es altamente sensible al diseño responsive y a capturas en blanco (`27.5%`). Con `ROC-AUC = 0.5584` (IC 95% `[0.4739, 0.6492]`, que cruza `0.50`), las características visuales actuales **no discriminan por sí mismas entre páginas legítimas y de phishing**.
2. **Compromiso de tamaño muestral en `M3_authentic_cdp`:** Aunque `M3_authentic_cdp` recupera 1 falso negativo adicional respecto a `M2` (`Recall = 92.86%` [`26/28`] frente a `89.29%` [`25/28`]), introduce `4` falsos positivos (`FPR = 7.27%` frente a `0.00%` en `M2`), reduciendo el F1 de `0.9434` a `0.8966` ($\Delta\text{F1} = -0.0468$, IC 95% `[-0.1310, +0.0277]`, McNemar exacto $p = 0.3750$, no significativo). Esto ocurre porque entrenar las 82 variables sobre solo $N = 312$ muestras reduce en $13.5\times$ los datos disponibles para ajustar las 50 variables no visuales respecto a `M2` ($N = 4,219$).
3. **Implicación para el artículo:** El componente visual actual debe reportarse honestamente como una **exploración negativa / resultado nulo informativo**: demuestra la factibilidad técnica de captura Chrome CDP ($\text{mediana} = 2.20\text{ s}$), pero prueba que descriptores globales de luminancia y `pHash` de pantalla completa son insuficientes frente a un clasificador `M2` que ya alcanza `ROC-AUC = 0.9929` con URL + Infraestructura + DOM, motivando el uso de detectores de logotipos locales (YOLO/CLIP/ViT) en trabajos futuros.

---

## PARTE II. COMPONENTE LLM (`Groq`, Sección 10)

### 2.1 Auditoría Separada de los Dos Experimentos con LLM

Siguiendo estrictamente la Sección 10 del protocolo, separamos los dos experimentos existentes y ampliamos el segundo con llamadas controladas en vivo sobre muestras legítimas abstenidas (`label = 0`) para disponer de ambas clases:

#### Experimento LLM-1: Benchmark Histórico Exploratorio con `llama-3.1-8b-instant` ($N_{\text{ITE}} = 100 \rightarrow N_{\text{CC}} = 30$)
- **Fuente verificable:** [`artifacts/llm-v2-benchmark/benchmark_summary.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/llm-v2-benchmark/benchmark_summary.json) y [`detailed_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/llm-v2-benchmark/detailed_results.json).
- **Atriición documental:** De `100` URLs muestreadas (`50` phishing, `50` legítimas), **`70` (`70.0%`) fallaron durante la descarga previa de HTML** (`38` phishing caídas y `32` legítimas con bloqueo/timeout), quedando **$N = 30$ muestras evaluadas por el LLM** (`12` phishing y `18` legítimas; nota: una muestra phishing tuvo `llm_prob = 0.0` por error de parseo).
- **Descalibración severa como clasificador aislado:** `llama-3.1-8b-instant` asignó una probabilidad media de `0.0900` a sitios legítimos y de solo **`0.1333` a sitios de phishing** (ninguna muestra de phishing superó `0.30`). Por ello:
  - En el umbral estándar $\tau = 0.50$, el LLM aislado obtuvo **`TP = 0`, `Recall = 0.0%`, `F1 = 0.0000`** (`Brier = 0.3208`, `ECE = 0.3393`).
  - Incluso bajando el umbral a $\tau = 0.20$, el LLM aislado solo obtuvo `TP = 2/12` (`Recall = 16.67%`, `F1 = 0.2667`), mientras que **`M0` solo en esas mismas $N = 30$ muestras alcanzó `F1 = 0.7368` (`Precision = 100%`, `Recall = 58.33%`, `ROC-AUC = 0.8889`)**.
  - Al promediar `M0 + LLM` (`m0_plus_llm_hybrid`), el `F1` permaneció exactamente igual al de `M0` (`0.7368`), aunque el ordenamiento de ranking mejoró ligeramente (`ROC-AUC = 0.9259` vs. `0.8889`).

#### Experimento LLM-2: Desempatador en Vivo sobre la Abstención de `M5` con `openai/gpt-oss-20b` ($N = 29$ abstenidas $\rightarrow N = 9$ evaluadas en vivo con ambas clases)
- **Fuente verificable:** [`artifacts/corrected_audit/llm_abstained_live_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/llm_abstained_live_results.json) combinado con las evaluaciones suplementarias en vivo registradas en [`06_visual_y_llm_results.json`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/fase6_visual_llm/06_visual_y_llm_results.json).
- **Alcance y cuota API:** Sobre las `29` muestras abstenidas por `M5` (`21` phishing y `8` legítimas), se completaron **`9` evaluaciones reales extremo a extremo en la API de Groq (`openai/gpt-oss-20b`)**: `7` phishing y `2` legítimas, antes de que el límite de *Tokens Per Minute* (TPM `HTTP 429`) del tier gratuito restringiera el resto del lote.
- La Tabla 4 compara el rendimiento en este subconjunto verdaderamente ambiguo ($N = 9$: `7` phishing, `2` legítimas) donde la cascada `M4` tenía alta incertidumbre ($\mathcal{H} \ge 0.15$).

| Estrategia sobre Muestras Abstenidas por `M5` ($N = 9$: `7` Phish, `2` Legit) | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 (IC 95% Bootstrap) | FPR | ROC-AUC | PR-AUC | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|
| **Cascada Forzada Sola (`M4` sin LLM)** | `4` | `1` | `1` | `3` | `0.5556` | `0.8000` | `0.5714` | `0.6667 [0.2500, 0.9375]` | `0.5000` | `0.5714` | `0.8598` | `0.3672` |
| **LLM Zero-Shot Solo (`openai/gpt-oss-20b`, $\tau=0.50$)** | `5` | `1` | `1` | `2` | `0.6667` | `0.8333` | `0.7143` | `0.7692 [0.4444, 1.0000]` | `0.5000` | `0.6786` | `0.9127` | `0.2488` |
| **Híbrido `50% Cascada + 50% LLM` ($\tau=0.50$)** | **`5`** | **`0`** | **`2`** | **`2`** | **`0.7778`** | **`1.0000`** | **`0.7143`** | **`0.8333 [0.5455, 1.0000]`** | **`0.0000`** | **`0.7143`** | **`0.9325`** | **`0.2660`** |

---

### 2.2 Evaluación Separada: (A) Clasificador/Desempatador vs. (B) Explicación Semántica y Costo Operativo

1. **Como clasificador o desempatador cuantitativo:**
   - En muestras generales ($N = 30$), un LLM pequeño zero-shot (`llama-3.1-8b-instant`) está **severamente subcalibrado** (`F1 = 0.0000` en $\tau=0.50$) y **no debe utilizarse para sobrescribir la probabilidad de `M2`**, lo que confirma que el Bug 6 detectado en [`src/phishguard_Infra/worker.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_infra/worker.py#L243-L249) (`final_prob = llm_prob`) es perjudicial.
   - En cambio, cuando se restringe exclusivamente al **`4.20%` de muestras abstenidas por `M5`** y se combina en ensamble `50/50` con la probabilidad de la cascada (`cascade_plus_llm_50_50`), el LLM (`openai/gpt-oss-20b`) muestra indicios preliminares favorables ($N = 9$): rescata falsos negativos donde la cascada dudaba (p. ej., `https://zimbirti.com/click/` pasa de `p_cascada = 0.1162` a `p_llm = 0.9200`; `https://anahirschle.com.br/.../eovlogin.php` pasa de `0.4095` a `0.7500`) y corrige el falso positivo legítimo `https://digitalreef.com/` (`p_cascada = 0.7215`, `p_llm = 0.2500`, media `0.4857 < 0.50`), elevando el F1 de `0.6667` a `0.8333`. Sin embargo, dado el tamaño muestral reducido ($N = 9$, IC 95% `[0.5455, 1.0000]`), este resultado es **estrictamente exploratorio y estadísticamente inconcluso**.
2. **Como generador de explicación diagnóstica estructurada:**
   - El prompt estructurado produce justificaciones en español consistentes con las señales léxicas y de ruta cuando hay indicadores claros (identificando correctamente `Chase Bank` en `https://chaselogin91.web.app/`, el abuso de ruta administrativa WordPress en `fucat-value.com/wp-includes/...` y el endpoint de captura de credenciales `eovlogin.php`).
   - **Riesgo de alucinación benigna:** En dominios de phishing alojados en plataformas gratuitas sin palabras clave de marca obvias en la URL ni HTML capturado (p. ej., `https://starvision.pages.dev/` y `http://goemediapercetakan.com/`), el LLM afirma con exceso de confianza (`llm_prob = 0.15`) que el sitio es seguro porque *"no presenta indicios de suplantación de marca conocida"*, induciendo una falsa sensación de seguridad si se muestra al usuario sin advertencia de incertidumbre.
3. **Telemetría real de latencia, consumo de tokens y costo monetario ($N = 9$ llamadas medidas):**
   - **Consumo medio por consulta:** `466.0` tokens de prompt + `806.1` tokens de completado = **`1,272.1` tokens totales por llamada**.
   - **Latencia real en Groq:** $\text{Media} = 1,857.58\text{ ms}$, **$P_{50} = 1,842.73\text{ ms}$**, $P_{95} = 2,163.64\text{ ms}$.
   - **Costo económico proyectado:** Si se invocara en el `100%` de las URLs, costaría `$0.444 USD` por cada `1,000` URLs (`gpt-oss-20b`) o `$0.274 USD` (`llama-3.1-8b`). Gracias al filtrado selectivo de `M5` (`4.20%` de abstención), el costo amortizado cae un **`95.8%`**, situándose en **`$0.0186 USD` (`1.86` centavos de dólar) por cada `1,000` URLs inspeccionadas**.
