# AUDITORIA_SISTEMA.md: Auditoría Técnica y Estructural del Sistema PhishPe

**Fecha de Auditoría:** 2026-10-22  
**Rama de Investigación:** `research/risk-aware-policy` (derivada de `corrections-phase2`, commit `058169a99786a42203d7db27d5da994b6ceb61c9`)  
**Investigador Principal & Desarrollador Responsable:** Equipo R&D RAEA-Phish  

---

## 1. Alcance y Objetivos de la Auditoría

El presente documento audita la arquitectura de software, modelos entrenados, flujos de datos y políticas de inferencia existentes en la plataforma **PhishPe / PhishGuard Pro** con el fin de fundamentar la integración del método novedoso **RAEA-Phish** (*Risk- and Availability-Aware Adaptive Evidence Acquisition*).

Se verifican:
1. Módulos de modelos $M0$ a $M5$.
2. Subsistemas de adquisición de evidencia multimodal (DNS, TLS, HTTP, DOM, Renderizado CDP/Visual).
3. Políticas de orquestación existentes (Cascada de Entropía de Shannon, perfiles SLA, política conservadora).
4. Datasets, particiones congeladas y conjuntos de validación externa.
5. Puntos de integración y contratos de interfaces.

---

## 2. Inventario Estructural de Modelos $M0$–$M5$

| Modelo | Modalidades Integradas | Dimensiones (Variables) | Archivo Modelo Congelado | Rol Operativo |
| :--- | :--- | :--- | :--- | :--- |
| **M0** | Características léxicas de URL (autoridad/host) | 11 variables (16 completas) | `artifacts/m0-real/model.joblib`<br>`artifacts/url-baseline-0.2.0/model.joblib` | Inferencia ultrarrápida ($< 0.2\text{ ms}$) en endpoint/extensión. |
| **M1** | M0 + Infraestructura de Red (DNS, IP, ASN, TLS) | 34–36 variables | `artifacts/m1-real/model.joblib` | Análisis de red pasivo/activo en gateway. |
| **M2** | M1 + Contenido DOM / HTML | 50–62 variables | `artifacts/m2-real/model.joblib` | Extracción estructural de página web descargada. |
| **M3** | M2 + Visión por Computadora (Playwright CDP) | 75–82 variables | `artifacts/corrected_audit/m3-authentic-cdp/model.joblib`<br>`artifacts/m3-real/model.joblib` | Inspección visual profunda y similitud perceptual de marca. |
| **M4** | Multimodal Monolítico (todas las modalidades) | 75–82 variables | Pipeline forzado (M0 $\to$ M1 $\to$ M2 $\to$ M3) | Benchmark estático de máxima evidencia sin parada temprana. |
| **M5** | Cascada Adaptativa basada en Incertidumbre | Dinámico ($M0 \to M1 \to M2 \to M3$) | `src/phishguard_orchestrator/engine.py` | Parada temprana si $H(p) \le 0.15$; abstención si $H(p) > 0.20$ o $0.50$. |

---

## 3. Auditoría de Adquisición de Modalidades y Dependencias Físicas

### 3.1. Infraestructura de Red (DNS / TLS)
- **Implementación:** `src/phishguard_infra/` y `src/phishguard_ml/infrastructure.py`.
- **Mecanismos:** Resolución DNS asíncrona, consulta de certificados TLS vía socket SSL con timeout configurable.
- **Riesgo Operativo:** Alta tasa de bloqueo o fallo de red en sitios de phishing ya retirados o en listas de bloqueo perimetrales (`blocked` o `error` en ~48% de phishing en Cohorte 2).

### 3.2. Contenido DOM / HTML
- **Implementación:** `src/phishguard_content/` y `src/phishguard_ml/content.py`.
- **Mecanismos:** Descarga HTTP GET con `httpx`/`urllib` respetando límites de tamaño y tiempo; parseo BeautifulSoup/lxml para extraer formularios de autenticación, scripts externos, iframes ocultos y anclas sospechosas.
- **Riesgo Operativo:** En sitios de phishing, el fallo de descarga o parseo alcanza el 85.3% en entornos vivos debido a servidores caídos, antibots o códigos de error HTTP 404/403/500.

### 3.3. Evidencia Visual y Sandbox CDP
- **Implementación:** `src/phishguard_visual/`, `src/phishguard_api/browser_sandbox.py` y `phishguard_api.sandbox_manager`.
- **Mecanismos:** Playwright headless en contenedor Docker aislado con red interna no enrutable hacia LAN privada, renderizando screenshot y extrayendo hashing perceptual (pHash/dHash).
- **Riesgo Operativo:** Latencia elevada (> 1,200 ms) y consumo intensivo de memoria; propensa a fallar si la página no carga el DOM base.

---

## 4. Auditoría de Políticas de Decisión Existentes

### 4.1. Cascada Estándar de Entropía de Shannon (`engine.py`)
- **Regla:** Dado el score $p \in [0, 1]$, calcula la incertidumbre como $H(p) = - [p \log_2 p + (1-p) \log_2(1-p)]$.
- **Criterio de parada temprana:** Si $H(p) \le 0.15$ (equivalente a $p \le 0.0237$ o $p \ge 0.9763$), detiene la cascada y clasifica inmediatamente.
- **Vulnerabilidad Forense Detectada:** Si un sitio de phishing tiene una URL estructurada de forma engañosamente benigna (p. ej., subdominio de hosting legítimo, CDN o URL acortada), $M0$ predice $p_0 \approx 0.01$. La entropía resultante es $H(p_0) \approx 0.08 \le 0.15$. La cascada se detiene en la etapa 0 y declara **legítimo**. Esto origina un **Falso Negativo Silencioso Prematuro** que habría sido detectado si se hubiese consultado $M1$ ($p_1 = 0.985$) o $M2$.

### 4.2. Política Conservadora Asimétrica (`fase2_05_cascada_ablaciones.py`)
- **Regla heurística:** Prohíbe la detención temprana benigna en $M0$ a menos que $p_{M0} \le 0.02$, forzando consultar al menos infraestructura de red ($M1$) para toda muestra con sospecha mínima.
- **Limitación Científica:** Es una regla estática ad-hoc. No considera si la red está disponible, no modela formalmente el riesgo de Bayes ni el coste de adquisición esperado, ni pondera la probabilidad de fallo de la siguiente modalidad.

### 4.3. Perfiles SLA (`profiles.py`)
- Define tres perfiles estáticos: `REAL_TIME_BROWSER` (presupuesto 0), `ENTERPRISE_GATEWAY` (presupuesto 2), `DEEP_FORENSIC` (presupuesto 3). No hay optimización secuencial dinámica basada en el estado de la URL.

---

## 5. Auditoría de Datasets y Particiones Congeladas

1. **Corpus Base 0.1.0:** 176,201 URLs en `data/processed/0.1.0/samples.csv`, con particiones congeladas en `splits/` (`conventional`, `host_unseen`, `temporal`, `temporal_host_unseen`).
2. **Evaluación Interna Multimodal:** Particiones de validación ($N=702$) y prueba ($N=691$ Complete-Case, $N=1,500$ ITE) con predicciones congeladas en `artifacts/m0-real/` a `m3-real/`.
3. **Validación Externa Cohorte 2:** $N=1,200$ URLs a nivel URL (600 phishing de OpenPhish/PhishTank/URLhaus/CERT.pl, 600 legítimas de Majestic/Gov/Edu disjuntas de 0.1.0) y $N=600$ con sondeo multimodal en vivo en `artifacts/corrections_phase2/eval/probe_predictions.csv` y `probe_raw.jsonl`.

---

## 6. Conclusión de la Auditoría

El repositorio cuenta con una infraestructura sólida de extracción de características y modelos preentrenados congelados. Sin embargo, su mecanismo de orquestación actual adolece de una dependencia unidimensional en la entropía de Shannon, ignorando la asimetría del riesgo de falsos negativos y la probabilidad de indisponibilidad de modalidades en la web activa. Esta brecha fundamenta el diseño e integración del nuevo método **RAEA-Phish**.
