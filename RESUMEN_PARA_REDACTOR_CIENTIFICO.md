# ENTREGABLE C. GUÍA CIENTÍFICA Y EDITORIAL PARA EL REDACTOR DEL MANUSCRITO (REVISTA POLITÉCNICA — SCOPUS)

**Fecha:** 2026-10-13 UTC  
**Rama de evidencia:** `experimental/validacion-scopus-fase2` (Commit base: `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7`)  
**Nota de integridad:** Conforme a las instrucciones del encargo, los manuscritos originales [`PhishPe_Article_APA7.docx`](file:///d:/Proyects/Seguridad_Informacion/PhishPe_Article_APA7.docx) y [`PhishGuard_Article_APA7.docx`](file:///d:/Proyects/Seguridad_Informacion/PhishGuard_Article_APA7.docx) **no han sido modificados**. Esta guía indica exactamente cómo actualizar cada sección, tabla y figura con respaldo empírico completo.

---

## 1. Afirmaciones Científicamente Verificadas (`VERIFIED`) que Pueden Sostenerse con Firmeza

1. **Aporte significativo de la infraestructura de red (`M1`) y del contenido DOM (`M2`) sobre el análisis léxico de autoridad (`M0`):**
   - Sobre el conjunto de prueba interno libre de solapamiento de hosts ($N = 691$: `191` phishing, `500` legítimas), añadir las 23 características de infraestructura (`M1`) eleva el F1 de **`0.8658`** (IC 95% `[0.8256, 0.9016]`) a **`0.9188`** (IC 95% `[0.8861, 0.9480]`, $\Delta\text{F1} = +0.0530$, McNemar exacto $p = 1.69 \times 10^{-5}$, ajustado Holm-Bonferroni $p_{\text{Holm}} = 6.76 \times 10^{-5}$) y reduce la tasa de falsos positivos (`FPR`) en un **`87.5%`** (de `3.20%` [`16/500`] a `0.40%` [`2/500`]).
   - La fusión de las tres modalidades en `M2` (URL + Infraestructura + DOM HTML, 50 variables) alcanza **`F1 = 0.9315`** (IC 95% `[0.9014, 0.9577]`, `Precision = 98.84%`, `Recall = 87.96%`, `FPR = 0.40%`, `ROC-AUC = 0.9735`), superando significativamente tanto a `M0` ($\Delta\text{F1} = +0.0658$, $p = 1.18 \times 10^{-7}$, $p_{\text{Holm}} = 7.08 \times 10^{-7}$) como al baseline clásico de n-gramas de caracteres de host (`Baseline2A_CharNgram_HostOnly_LR`, `F1 = 0.8480`, $\Delta\text{F1} = +0.0835$, $p = 1.0 \times 10^{-6}$).
2. **Eficiencia computacional y calibración de la Cascada Adaptativa (`M4`):**
   - La cascada calibrada `M4` alcanza **`F1 = 0.9248`** (IC 95% `[0.8931, 0.9524]`), **`Precision = 99.40%`**, **`FPR = 0.20%` (`1/500`)** y el mejor error de calibración del estudio (**`Brier = 0.0309`, `ECE = 0.0209`**), sin diferencia estadísticamente significativa en F1 respecto al modelo monolítico `M2` ($\Delta\text{F1} = -0.0067$, McNemar $p = 0.5488$), pero ahorrando el **`71.64%` de las descargas e inspecciones DOM HTML** (`495/691` muestras resueltas antes de `M2`, con costo medio de $\bar{m} = 1.79$ etapas por URL frente a $3.00$ en `M2`).
3. **Generalización externa real y demostración empírica de la paradoja de modelos de URL completa (`Fase II` y `Fase IV`):**
   - En la nueva cohorte externa independiente ($N = 1,054$: `600` phishing de `OpenPhish`, `CERT.PL` y `Phishing.Army`; `454` legítimas de `Majestic`, `Hipo Universities` y `CISA .gov`, con `0.0%` de solapamiento de dominios registrados PSL con `samples.csv`), demostramos por qué los modelos de la literatura que utilizan las 36 variables de la URL completa (`Baseline1A_FullURL36_RF`, `Baseline1B_FullURL36_HGB`) o n-gramas sobre la URL completa (`Baseline2B_CharNgram_FullURL_LR`) son engañosos: aunque logran `F1 = 0.949–0.989` en el test interno explotando el atajo de que Tranco contiene URLs raíz y PhishTank rutas largas, **en el conjunto externo caen a `ROC-AUC = 0.4749–0.6730`**, mientras que los modelos restringidos a autoridad de PhishPe (`M0` con normalización `strip_www()`: **`ROC-AUC = 0.7530`, `PR-AUC = 0.8135`**; `HybridM0Model`: **`ROC-AUC = 0.8077`, `FPR = 1.32%`** con Tranco y **`ROC-AUC = 0.7710`, `FPR = 2.20%`** sin Tranco) generalizan de forma significativamente superior.
   - Asimismo, en la sonda multimodal externa en vivo ($N_{\text{CC}} = 104$), tras normalizar el prefijo `www.`, los modelos congelados muestran una progresión monótona: `M0` (`ROC-AUC = 0.7057`) $\rightarrow$ `M1` (`ROC-AUC = 0.8263`) $\rightarrow$ **`M2` (`ROC-AUC = 0.9248`, `PR-AUC = 0.9423`, `Precision = 96.30%`, `FPR = 2.00%`)**.
4. **Viabilidad operativa de la integración Extensión + Cascada (`Configuración C`):**
   - La arquitectura integrada `HybridM0 (Etapa 0) -> M1 -> M2/M5` resuelve el `73.81%` del tráfico en la etapa rápida del cliente ($P_{50} = 51.51\text{ ms}$ en interno y $68.33\text{ ms}$ en externo, una aceleración mediana de **$23.4\times$** frente a la cascada API pura `Configuración B`), manteniendo `FPR = 0.00%` y `F1 = 0.9178` en $N=691$ y elevando el F1 externo en $N_{\text{CC}}=104$ de `0.4789` (`Config A`) a **`0.5600` (`ROC-AUC = 0.8380`)**.

---

## 2. Afirmaciones que Deben Matizarse Obligatoriamente (`MUST QUALIFY`)

1. **Comparaciones `M1 vs. M2` y `M2 vs. M3`:**
   - La ganancia marginal de `M2` sobre `M1` en $N=691$ (`+0.0127` F1, `0.9315` vs. `0.9188`) tiene $p = 0.2100$ en McNemar exacto ($p_{\text{Holm}} = 1.0000$). No debe escribirse que *"M2 supera estadísticamente a M1 en F1 global"*, sino que *"M2 aporta una mejora numérica consistente (+1.27 pp en F1 interno y +9.85 pp en ROC-AUC externo vivo, pasando de 0.8263 a 0.9248), aunque sobre N=691 la diferencia pareada de F1 no alcanza significación estadística al nivel $\alpha=0.05$"*.
2. **Clasificación selectiva `M5` y política sobre las `29` abstenciones (`4.20%`):**
   - El valor `F1 = 0.9538` (`Recall = 91.18%`, `Precision = 100.0%`, `FPR = 0.00%`) de `M5` corresponde **exclusivamente al subconjunto decidido ($N = 662$, cobertura `95.80%`)**.
   - El redactor debe reportar en la misma tabla las dos políticas operativas sobre el denominador completo ($N = 691$):
     - Bajo política **`M5 Fail-Open`** (permitir el paso silencioso de la abstención): `F1 = 0.8857`, `Recall = 81.15%`, porque **`21` de las `29` muestras abstenidas (`72.41%`) son phishing reales**.
     - Bajo política **`M5 Fail-Closed` / Advertencia Cautelar** (bloquear o mostrar advertencia intersticial en las `29` abstenciones): **`F1 = 0.9387`, `Recall = 92.15%` (`176/191`), `Precision = 95.65%`, `FPR = 1.60%` (`8/500`)**, superando significativamente a `M4` ($\Delta\text{F1} = +0.0139$, McNemar $p = 0.0074$).
   - Además, debe explicarse que sobre el mismo subconjunto decidido ($N = 662$), `M2` monolítico (`F1 = 0.9636`, `11` FN) tiene 4 falsos negativos menos que `M5` (`15` FN) debido a `12` muestras de phishing que salen prematuramente en `M0` con baja incertidumbre, y que la política **`Cascada Conservadora (M1 obligatorio para salidas benignas)`** elimina esos 12 errores alcanzando **`F1 = 0.9341`** en $N = 691$.
3. **Efecto del prefijo `www.` en la validación externa de `M0–M2`:**
   - Debe explicarse con transparencia que el conjunto de entrenamiento `0.1.0` construyó las URLs de Tranco sin `www.`, haciendo que `M0` trate el prefijo `www.` como un subdominio sospechoso (`FPR = 94.0%` en universidades con `www.` en URL cruda), y mostrar cómo la simple normalización canónica `strip_www()` sin reentrenar los modelos reduce la FPR externa de `46.70%` a `9.69%` y eleva el `ROC-AUC` de `M0` de `0.4859` a `0.7530`.
4. **Desempeño del LLM (`Groq`) como desempatador exploratorio:**
   - En muestras generales ($N = 30$), `llama-3.1-8b-instant` está descalibrado (`F1 = 0.0000` en $\tau = 0.50$). En cambio, sobre las muestras ambiguas abstenidas por `M5` ($N = 9$ evaluadas en vivo con `openai/gpt-oss-20b`: `7` phishing y `2` legítimas), el ensamble `50% Cascada + 50% LLM` alcanza `F1 = 0.8333` (`Accuracy = 77.78%`, `0` FP, `2` FN) frente a `F1 = 0.6667` de la cascada forzada sola, con un costo amortizado de **`$0.0186 USD` por cada `1,000` URLs**. Debe presentarse explícitamente como **evidencia piloto exploratoria ($N = 9$)** limitada por la cuota TPM de la API gratuita.

---

## 3. Afirmaciones que Deben Eliminarse o Corregirse (`REJECTED / DO NOT CLAIM`)

1. **NO afirmar que el modelo visual `M3` mejora el rendimiento de `M2`:**
   - Ni en el conjunto global ($N = 691$, donde el `88.2%` de los vectores visuales son ceros y `M3` obtiene `F1 = 0.9308` vs. `0.9315` de `M2`, $p = 1.0000$) ni en la cohorte con capturas reales Chrome CDP ($N = 83$, donde `M2` obtiene `F1 = 0.9434, ROC-AUC = 0.9929` frente a `F1 = 0.8966, ROC-AUC = 0.9789` de `M3_authentic_cdp`, $p = 0.3750$), la etapa visual actual aporta ganancia predictiva. Además, el clasificador entrenado solo con las 32 variables visuales (`Visual_Only_32feat`) obtiene `ROC-AUC = 0.5584` (IC 95% `[0.4739, 0.6492]`). Presentar la etapa visual como una **lección experimental negativa sobre descriptores globales de píxeles/pHash** frente a un techo `M2` de `0.9929` fortalecerá enormemente la credibilidad ante los revisores de Scopus.
2. **NO utilizar ni mencionar las 91 imágenes de `artifacts/screenshots/` como capturas de navegador:**
   - Esas 91 imágenes proceden de un renderizador sintético (`PIL.ImageDraw`). Toda referencia a capturas reales debe referirse exclusivamente a los **`467` registros `live_cdp`** (`83` en test) de `visual-results-authentic-cdp.jsonl` y a las **`40` capturas PNG de Chrome CDP** en `artifacts/authentic-cdp-screenshots/`.
3. **NO atribuir las métricas de la cascada experimental `M4/M5` a la extensión de navegador actual (`Configuración A`):**
   - La extensión en producción consume `POST /check` (`HybridM0Model`), mientras que la cascada `M0–M3` reside en `/analyze/cascade`. Deben presentarse como tres configuraciones diferenciadas (`Config A`, `Config B` y `Config C`).
4. **NO presentar el `F1 = 0.9999` de `url-baseline-0.2.0` como un resultado válido de detección:**
   - Debe citarse únicamente como ejemplo del artefacto de contaminación por longitud de ruta (`path_length` shortcut) que motivó restringir `M0` a las 11 variables de autoridad.

---

## 4. Tablas y Figuras Listas para Insertar en el Manuscrito

### Figuras a 300 DPI (en [`artifacts/validacion_scopus_fase2/figures/`](file:///d:/Proyects/Seguridad_Informacion/artifacts/validacion_scopus_fase2/figures)):
1. **`fig1_external_generalization_paradox.png`**: Muestra (a) la paradoja de generalización entre modelos de URL completa y modelos de autoridad del host en $N=691$ interno vs. $N=1,054$ externo, y (b) la progresión multimodal `M0 -> M1 -> M2 -> Config C` en la cohorte externa viva ($N_{\text{CC}}=104$).
2. **`fig2_extension_latency_and_pareto.png`**: Muestra (a) los percentiles $P_{50}$ y $P_{95}$ de latencia real medida en las Configuraciones A (fría/cálida), B y C frente al límite de timeout de `6,000 ms`, y (b) la frontera de Pareto entre costo medio de etapas evaluadas y F1-Score en $N=691$.
3. **`fig3_calibration_and_prevalence_sensitivity.png`**: Muestra (a) las curvas de confiabilidad de 10 bins (`M0`, `M2`, `M4` calibrada, `HybridM0`) y (b) la sensibilidad del Valor Predictivo Positivo (`PPV`) ante prevalencias operativas entre `0.1%` y `50%`.
4. **`fig4_visual_cdp_and_adversarial_robustness.png`**: Muestra (a) la evaluación controlada sobre el subconjunto Chrome CDP auténtico ($N=83$) incluyendo `Visual_Only_32feat`, y (b) la tasa de éxito de ataque (`ASR`) y evasión silenciosa en las 6 familias adversariales ($N=191$).
