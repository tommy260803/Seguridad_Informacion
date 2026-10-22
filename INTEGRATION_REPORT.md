# INTEGRATION_REPORT.md: Informe de Integración y Pruebas Operativas

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Componentes Evaluados:** Backend FastAPI (`phishguard_api`), Worker Asíncrono (`worker.py`), Orquestador RAEA (`phishguard_orchestrator.raea`), Extensión Chrome Manifest V3.  
**Artefactos Generados:**
- `artifacts/raea/failure_scenarios.csv`
- `artifacts/raea/browser_tests.csv`
- `artifacts/raea/operational_latency.csv`

---

## 1. Validación de Escenarios de Fallo Controlado

Se sometió a RAEA-Phish a 5 condiciones de estrés e inaccesibilidad en entornos web reales y simulados:

| ID Escenario | Condición Simulada | Modos Consultados | Decisión Emitida | Comportamiento Observado | Estado |
| :--- | :--- | :---: | :---: | :--- | :---: |
| **FS-01** | Fallo DNS (NXDOMAIN / Dominio retirado) | `url`, `network`, `html` | `uncertain` | El modelo detecta fallo de red y emite abstención protectora sin asumir malicia automática (Regla 11). | **PASSED** |
| **FS-02** | Fallo TLS (Certificado vencido / Host mismatch) | `url`, `network`, `html` | `uncertain` | Identifica bloqueo de handshake; evita timeout innecesario de descarga HTTP. | **PASSED** |
| **FS-03** | Error HTTP 404 / 500 (Kit de phishing borrado) | `url`, `network`, `html` | `uncertain` | No declara erróneamente legítimo; registra incidencia y emite advertencia de incertidumbre. | **PASSED** |
| **FS-04** | Timeout en Renderizado CDP / Sandbox | `url` | `phishing` | Al tener alta certeza inicial ($p_0 = 0.82 \to Q_{\text{phish}} = 0.18$), decide inmediatamente sin consumir memoria en sandbox. | **PASSED** |
| **FS-05** | Host por IP numérico con $p_{M0} = 0.01$ | `url`, `network` | `legitimate` (tras red) | La Guarda Benigna en $M0$ **bloqueó la salida benigna prematura**, forzando la consulta de red antes de autorizar el acceso. | **PASSED** |

---

## 2. Validación de Integración con la Extensión Chrome Manifest V3

Las pruebas de integración confirmaron la compatibilidad con la extensión del navegador:
1. **Contrato de API (`/check`):** La respuesta JSON cumple con la especificación requerida por `background.js` (campos `decision`, `probability`, `model`, `reputation`, `risk_breakdown`). Latencia de respuesta rápida: **$4.2\text{ ms}$** (cumple SLA $\le 5\text{ ms}$).
2. **Filtro Bloom Tranco Top-1M:** Sitios de alta reputación global resuelven en **$0.08\text{ ms}$** sin invocar clasificadores pesados.
3. **Caché Local de Navegador:** Tiempos de respuesta de **$0.02\text{ ms}$** para URLs en caché local (TTL 180 segundos).
4. **Handoff Asíncrono (`/analyses`):** URLs sospechosas con necesidad de análisis en profundidad se encolan con éxito hacia PostgreSQL, procesándose en segundo plano por el worker con un overhead de encolado de **$12.5\text{ ms}$**.
5. **Redirección de Advertencia:** Veredictos de phishing activan la vista `warning.html` cancelando la navegación interactiva de forma segura.

---

## 3. Perfil de Latencias Operativas

| Etapa Operativa | Descripción | Muestras ($N$) | Latencia Media | P50 (Mediana) | P95 | Cumplimiento SLA |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **$M0$ Léxico Autoridad** | Inferencia de URL rápida | 500 | 0.085 ms | 0.085 ms | 0.110 ms | **100.0%** (SLA $\le 5\text{ ms}$) |
| **Motor RAEA (Decisión)** | Cálculo de riesgos y selección de acción | 500 | 0.450 ms | 0.449 ms | 0.534 ms | **100.0%** (SLA $\le 2\text{ ms}$) |
| **RAEA Cascada Completa** | Flujo adaptativo extremo a extremo con red | 300 | 1,184.2 ms | **886.5 ms** | 3,612.3 ms | **98.3%** (SLA $\le 5\text{ s}$) |

El overhead computacional del algoritmo de decisión RAEA es menor a **$0.5\text{ ms}$**, lo que confirma que el coste de la política es despreciable frente al ahorro de red obtenido.
