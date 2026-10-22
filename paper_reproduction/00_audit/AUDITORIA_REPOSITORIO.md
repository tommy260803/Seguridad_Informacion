# AUDITORÍA INTEGRAL DEL REPOSITORIO PHISHPE / PHISHGUARD PRO
**Fecha de auditoría:** 2026-10-15  
**Auditor:** Arquitecto Senior de Software, Investigador de Ciberseguridad Aplicada, Ingeniero MLOps y Auditor de Reproducibilidad Científica  
**Repositorio:** `https://github.com/tommy260803/Seguridad_Informacion`  
**Ruta local:** `D:\Proyects\Seguridad_Informacion`  
**Rama activa:** `corrections-phase2`  
**Commit auditado:** `058169a78fb50af26bfd3ad9e95e547f782fee1c` (*Cierre de condiciones de las auditorías finales: freeze #5, revalidación offline y entregables regenerados*)  
**Commit base inmutable:** `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7` (*Merge branch 'origin/main' into main*)  
**Objetivo de publicación:** Fortalecer la evidencia científica reproducible para el artículo destinado a la **Revista Politécnica** (Ecuador).

---

## 1. Resumen Ejecutivo de la Auditoría

El proyecto **PhishPe** (con denominación operativa de extensión **PhishGuard Pro v1.2.0**) es un sistema experimental y funcional de defensa contra ataques de phishing web. Su arquitectura científica se basa en clasificadores progresivos multimodales (M0 $\to$ M1 $\to$ M2 $\to$ M3), orquestación adaptativa basada en la incertidumbre de la entropía de Shannon (M4) y decisión selectiva con abstención calibrada (M5), complementado con un modelo híbrido rápido síncrono para endpoints en Google Chrome Manifest V3.

La presente auditoría técnica y científica verificó la integridad del repositorio, el historial de cambios, los conjuntos de datos, los modelos entrenados, los scripts de evaluación, la extensión de navegador, la infraestructura de backend y la seguridad de los artefactos.

### Dictamen General
**ESTADO: APTO Y VERIFICADO PARA REPRODUCCIÓN CIENTÍFICA (CON CONDICIONES DE SEGURIDAD Y PENDIENTES DOCUMENTADOS)**
- **Verificación funcional:** 186 pruebas automatizadas (`pytest tests/`) ejecutadas con **186 PASS, 0 FAIL, 1 warning** (duración: 14.30 s).
- **Verificación de congelamiento offline:** Script `phase2n_revalidate_offline.py` ejecutado con **11/11 PASS**, garantizando que los modelos M0–M3, umbrales y predicciones históricas son idénticos byte a byte a los registrados bajo el Freeze #3 y #5.
- **Verificación de consistencia:** Script `verify_audit_report_consistency.py` ejecutado al **100% de coincidencia** con las métricas en disco (F1 M0: 0.8658, M1: 0.9252, M2: 0.9315, M3: 0.9286, M4: 0.9248, M5 selectivo: 0.9538 con precisión 1.0000).
- **Hallazgo crítico de seguridad:** Exposición de la clave privada de firma de la extensión Chrome en `extension.pem` (clave RSA 2048-bit) y el binario `extension.crx`, ambos rastreados en Git desde el commit `4d50414b` (2026-09-20). Se ha diseñado un plan de remediación estricto sin reescritura destructiva no autorizada.
- **Desajuste documental en manuscrito:** Los borradores en formato Word (`PhishGuard_Article_APA7.docx` y `PhishPe_Article_APA7.docx`) contienen texto y cifras sintéticas heredadas de fases pre-experimentales (`N = 2,000`, `1.52e-12`), requiriendo actualización textual prioritaria en la Fase 1.

---

## 2. Estructura y Módulos del Repositorio

El repositorio presenta una estructura modular organizada bajo el directorio estándar `src/`, con 11 paquetes principales y puntos de entrada CLI registrados en `pyproject.toml`:

```
D:\Proyects\Seguridad_Informacion\
├── src\
│   ├── phishguard_api\          # Servidor FastAPI, endpoints /check, /analyses, worker y telemetría
│   ├── phishguard_common\       # Entorno, logging, utilitarios comunes
│   ├── phishguard_content\      # Analizador de contenido HTML, formularios, campos de contraseña
│   ├── phishguard_data\         # Adquisición de listas (Tranco, PhishTank, PSL), canonicalización y splits
│   ├── phishguard_explain\      # Generación de explicabilidad y atribución de características
│   ├── phishguard_infra\        # Extracción de características de red (DNS, TLS, WHOIS, IP host)
│   ├── phishguard_ml\           # Modelos M0-M3, entrenamiento, homóglifos, marcas, reglas y evaluación
│   ├── phishguard_orchestrator\ # Motor de entropía de Shannon, políticas adaptativas y transiciones
│   ├── phishguard_robustness\   # Perturbaciones adversariales (6 familias) y métricas de robustez
│   ├── phishguard_threat\       # Reglas de amenazas y firmas de evasión
│   └── phishguard_visual\       # Analizador y comparador visual de captura de pantalla y DOM
├── extension\                   # Extensión Chrome Manifest V3 (background service worker, popups, warning)
├── configs\                     # Mapeos de marcas por país, listas de reputación y configuraciones
├── data\                        # Datasets (raw: Tranco zip, PhishTank; processed: 0.1.0 samples.csv y splits)
├── artifacts\                   # Modelos congelados (.joblib), métricas, resultados E2E y cohorte2
├── scripts\                     # Scripts de experimentación, congelamiento (phase2a-n), barrido de secretos
├── tests\                       # Suite de pruebas unitarias y de regresión (186 tests)
├── sandbox\                     # Dockerfile y configuraciones para detonación aislada (CoreDNS, Squid)
└── docs\                        # Documentación complementaria y planes de auditoría histórica
```

---

## 3. Implementación de Modelos: M0 a M5 y Modelo Híbrido

### M0: Modelo Léxico de URL
- **Código:** [`src/phishguard_ml/features.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/features.py), [`src/phishguard_ml/training.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/training.py).
- **Características (11 variables en perfil `authority_only`):** Longitud de host, conteo de etiquetas, conteo de subdominios, entropía de Shannon del host, conteo de dígitos, presencia de IP como host, ratio de caracteres especiales, guiones, puntos y tokens sospechosos.
- **Normalización (BUG-07):** Función `_strip_www()` en inferencia para descontar el subdominio `www.` y evitar falsos positivos masivos sobre dominios legítimos.
- **Pesos congelados:** [`artifacts/url-baseline-0.2.0/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/url-baseline-0.2.0/model.joblib) y [`artifacts/m0-real/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/m0-real/model.joblib).
- **Métrica histórica (host_unseen Complete-Case N=691):** F1 = 0.8658, Recall = 0.9240, FPR = 0.0320.

### M1: Modelo de Infraestructura de Red
- **Código:** [`src/phishguard_ml/infrastructure.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/infrastructure.py), [`src/phishguard_ml/m1_training.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/m1_training.py).
- **Características (36 variables = 11 URL authority + 25 Infra):** Registros DNS A/AAAA/MX/NS/TXT/SOA/CNAME, fallos de resolución, conteo de IPs, host con IP, TLS válido, emisor autofirmado, días hasta expiración, longitud de cadena de certificados, versión TLS y concordancia de SAN.
- **Pesos congelados:** [`artifacts/m1-real/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/m1-real/model.joblib).
- **Métrica histórica (host_unseen Complete-Case N=691):** F1 = 0.9252, Recall = 0.9766, FPR = 0.0240.

### M2: Modelo de Contenido DOM HTML
- **Código:** [`src/phishguard_ml/content.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/content.py), [`src/phishguard_content/analyzer.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_content/analyzer.py), [`src/phishguard_ml/m2_training.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/m2_training.py).
- **Características (62 variables = 36 M1 + 26 Content):** Conteo de enlaces externos/internos/vacíos, formularios sensibles con campos `password`, inputs de pago, campos ocultos, scripts externos, iframes sospechosos, longitud de texto y densidad de hipervínculos.
- **Pesos congelados:** [`artifacts/m2-real/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/m2-real/model.joblib).
- **Métrica histórica (host_unseen Complete-Case N=691):** F1 = 0.9315, Recall = 0.9942, FPR = 0.0240.

### M3: Modelo Multimodal Completo (con Visión)
- **Código:** [`src/phishguard_ml/visual.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/visual.py), [`src/phishguard_visual/analyzer.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_visual/analyzer.py), [`src/phishguard_ml/m3_training.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/m3_training.py).
- **Características (75 variables = 62 M2 + 13 Visuales):** Similitud visual perceptual de layout (SSIM, histogramas de color en HSV, bordes de Canny, densidad de componentes conexos, proporción texto/imagen). En cohorte auténtica CDP se extraen 32 características visuales puras.
- **Pesos congelados:** [`artifacts/m3-real/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/m3-real/model.joblib) y [`artifacts/corrected_audit/m3-authentic-cdp/model.joblib`](file:///d:/Proyects/Seguridad_Informacion/artifacts/corrected_audit/m3-authentic-cdp/model.joblib).
- **Métrica histórica (host_unseen Complete-Case N=691):** F1 = 0.9286, Recall = 0.9883, FPR = 0.0240. En evaluación CDP auténtica N=83: F1 = 0.8966, ROC-AUC = 0.9789.

### M4: Cascada Adaptativa Progresiva (Decisión Binaria Forzada)
- **Código:** [`src/phishguard_orchestrator/engine.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_orchestrator/engine.py), [`scripts/train_and_evaluate_all_real.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/train_and_evaluate_all_real.py).
- **Mecanismo:** Evalúa secuencialmente M0 $\to$ M1 $\to$ M2 $\to$ M3. En cada etapa calcula la entropía de Shannon $H(p) = -p\log_2 p - (1-p)\log_2(1-p)$. Si $H(p) \le \tau_{\text{esc}} = 0.15$, detiene la evaluación tempranamente (*early stopping*). Si se agotan las modalidades, fuerza una decisión binaria con $\tau_{\text{dec}} = 0.50$.
- **Métrica histórica (host_unseen Complete-Case N=691):** F1 = 0.9248 (166 TP, 25 FN), latencia mediana P50 reducida drásticamente frente a evaluar todas las modalidades monolíticamente.

### M4-Fixed: Cascada de 4 Etapas Fija
- **Código:** [`scripts/train_and_evaluate_all_real.py`](file:///d:/Proyects/Seguridad_Informacion/scripts/train_and_evaluate_all_real.py).
- **Mecanismo:** Ejecuta obligatoriamente las 4 etapas completas para todas las URLs sin parada temprana.
- **Métrica histórica:** F1 = 0.9029.

### M5: Cascada Adaptativa con Abstención Calibrada (*Selective Classification*)
- **Código:** [`src/phishguard_orchestrator/engine.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_orchestrator/engine.py) (función `decide_next`).
- **Mecanismo:** Si tras consultar las modalidades disponibles la incertidumbre residual supera el umbral de abstención ($H(p) > \tau_{\text{abst}}$), el sistema se abstiene de clasificar forzadamente y retorna `decision = "uncertain"`.
- **Métrica histórica (host_unseen Complete-Case N=691, subconjunto decidido N=647):** F1 = 0.9538, Precisión = 1.0000 (155 TP, 492 TN, 15 FN, **0 Falsos Positivos**), Cobertura = 93.63% (44 casos abstenidos).

### Modelo Híbrido M0 + Brand + Rules (Motor Síncrono de Extensión)
- **Código:** [`src/phishguard_ml/hybrid_model.py`](file:///d:/Proyects/Seguridad_Informacion/src/phishguard_ml/hybrid_model.py).
- **Componentes integrados:**
  1. Filtro Bloom de reputación Tranco Top 1M en memoria (`src/phishguard_data/reputation.py`).
  2. Modelo M0 léxico authority (11 variables).
  3. Detección de homóglifos Punycode con decodificación de etiquetas `xn--` y comparación visual contra esqueletos de marca (`homoglyphs.py`).
  4. Módulo de suplantación de marcas mediante distancia de edición Levenshtein DP fila móvil y similitud Jaro-Winkler (`brand_features.py`).
  5. 15 reglas heurísticas de detección rápida de vectores de ataque (`detection_rules.py`).
- **Rendimiento:** Latencia de inferencia $< 20\text{ ms}$, F1 con Tranco = 0.8798, FPR = 0.0000%.

---

## 4. Arquitectura de la Extensión Chrome e Integración con Backend

### Manifiesto y Permisos
- **Archivo:** [`extension/manifest.json`](file:///d:/Proyects/Seguridad_Informacion/extension/manifest.json) (Chrome Manifest V3).
- **Permisos:** `activeTab`, `storage`, `webNavigation`, `tabs`.
- **Host Permissions:** `http://localhost:*/*`, `http://127.0.0.1:*/*`, `https://ipwho.is/*`, `<all_urls>`.
- **Service Worker:** [`extension/background.js`](file:///d:/Proyects/Seguridad_Informacion/extension/background.js) (`type: module`).

### Flujo Operacional de Detección e Intercepción
1. **Captura del evento de navegación:** `chrome.webNavigation.onCommitted` escucha la carga en el frame principal (`frameId === 0`).
2. **Filtrado previo:** Omite esquemas no web (`chrome://`, `file://`), localhost/127.0.0.1, y dominios presentes en la lista de exclusiones temporales del usuario (`allowed_urls`, TTL 24 h).
3. **Caché en memoria local:** Consulta `analysisCache` (LRU Map con TTL 180 segundos). Si hay *cache hit*, la latencia navegación $\to$ insignia desciende a P50 = 82.6 ms (0 llamadas al backend).
4. **Consulta síncrona al backend:** Realiza petición HTTP `POST http://localhost:8080/check` con `{url, user_country}` bajo control de tiempo estricto mediante `AbortSignal.timeout(8000)` (presupuesto de 8 segundos, BUG-01 resuelto).
5. **Decisión e Intercepción:**
   - **Legítimo:** Emite insignia verde `✔`, tooltip con porcentaje de seguridad y permite la renderización libre de la página.
   - **Phishing / Riesgo Crítico:** Emite insignia roja `!`, registra los metadatos de alerta en `chrome.storage.local` y redirige inmediatamente la pestaña a `chrome-extension://<id>/warning.html` con parámetros explicativos (`target_brand`, probabilidad, reglas activadas).
   - **Advertencia / Inconsistencia Regional:** Emite insignia amarilla `?` y ofrece sugerencias locales.
6. **Degradación controlada (Fail-Open en fallo de backend):** Si el backend está apagado o agota el timeout de 8 s, la promesa fetch rechaza de inmediato (P50 = 1 ms), capturada por `catch`, evitando congelar el hilo de navegación del usuario.

### Pruebas E2E en Chrome Real
- **Binario utilizado:** Chrome-for-Testing 156.0.8078.4 (build Playwright `chromium-1248`).
- **Restricción de Chrome de marca:** Google Chrome comercial 155.0.8059.40 bloquea `--load-extension` desde la versión 137 (`branded_chrome_load_extension.log`).
- **Resultados de la batería:** 27 escenarios totales $\to$ **25 PASS, 2 NOT_RUN** (`l_concurrency`, `o_cascade_analyses`), 0 PARTIAL. 40 llamadas reales al backend local `:8080`, 4 errores todos deliberados por diseño, 0 espontáneos.

---

## 5. Registro de Metadatos de Versionado y Dependencias

| Parámetro | Valor Verificado en Auditoría |
|---|---|
| **Sistema Operativo** | Windows 11 Pro 64-bit (10.0.26200) |
| **Python** | 3.12.10 (`C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe`) |
| **Rama Git** | `corrections-phase2` (sincronizada con `origin/corrections-phase2`) |
| **Commit HEAD** | `058169a78fb50af26bfd3ad9e95e547f782fee1c` |
| **Commit Base Inmutable** | `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7` |
| **Freeze Manifiesto Vigente (#5)** | `110a954f7b99eced0bcea66a59700e23f8f6cea34f92db4fa9b4c6ec0fae5f62` |
| **Freeze Evaluación Histórica (#3)**| `0999ef95922262a6b796cf1dc2aa5515c095f47d179bf7945ba327ee78d92c41` |
| **Paquete Distribuible Evidencia** | `evidencia_phishpe_definitiva.zip` (332,804,835 bytes) |
| **SHA-256 ZIP Evidencia** | `369e193589c20fa637d5373eb54dc89f519df87753370e840f0510df2aba04af` |
| **Frameworks Principales** | FastAPI 0.111+, Uvicorn 0.53, Scikit-Learn 1.7.2, PyTorch 2.12.0, Playwright 1.64.0 |
| **Suite de Tests Automatizados** | Pytest 9.0.3 (186 passed en 14.30s) |
