# Metodología Experimental: Disponibilidad Multimodal, Sesgo de Selección y Estrategias de Fallback
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Protocolo Científico — Fase 3: Evaluación bajo Datos Faltantes y Condiciones Operativas*

---

## 1. Motivación y Problema Científico

Los clasificadores de phishing multimodales ($M_0$ Léxico, $M_1$ Red/Infraestructura, $M_2$ Contenido DOM/HTML, $M_3$ Visión por Computador) son evaluados comúnmente en la literatura bajo el supuesto idealizado de que **todas las modalidades están siempre disponibles para todas las URLs** (*Complete-Case Evaluation*).

Sin embargo, en el despliegue operacional real en Internet, este supuesto se derrumba debido a factores intrínsecos de la ciberseguridad:
1. **Vida Media Efímera del Phishing (*Ephemeral Phishing*):** Las campañas maliciosas tienen vidas medias de 4 a 36 horas antes de ser dadas de baja por registradores de dominios o proveedores de hosting (provocando errores de DNS vacío o HTTP 404).
2. **Entrega de Malware Directo sin Interfaz Web:** Feeds como URLhaus distribuyen scripts y binarios directos (`.bin`, `.sh`, `.exe`) que no poseen etiquetas HTML ni renderizado DOM.
3. **Contención y Políticas de Seguridad Sandbox:** Puertos inusuales (e.g., `:45209`, `:38636`) o direcciones IP privadas son deliberadamente bloqueados por las pasarelas y sandboxes para proteger al host de infecciones y escaneos de botnets.
4. **WAFs y Filtros Anti-Bot:** Servidores web y proxies de protección (Cloudflare, Akamai) rechazan peticiones automatizadas (HTTP 403, HTTP 499).

Evaluar un sistema de seguridad únicamente sobre el subconjunto de sitios web que responden con éxito a todas las consultas introduce un severo **Sesgo de Selección (*Survivorship Bias*)**. Este estudio evalúa rigurosamente el impacto de la disponibilidad multimodal y compara estrategias de recuperación (*fallback* y clasificación selectiva) bajo el estándar metodológico **Intention-To-Evaluate (ITE)**.

---

## 2. Definición Formal de las Poblaciones Evaluadas

```mermaid
graph TD
    subgraph Poblaciones_Evaluacion [Diseño Metodológico de Poblaciones]
        ITE[Intention-To-Evaluate - ITE<br>N = 600 URLs Balanceadas<br>300 Phishing / 300 Legítimas<br>Denominador Total de Despliegue Real]
        
        CC[Complete-Case - CC<br>N = 247 URLs con Éxito Multimodal<br>40 Phishing (13.3%) / 207 Legítimas (69.0%)<br>Subconjunto Sujeto a Sesgo de Supervivencia]
        
        INC[Casos Incompletos / Fallidos<br>N = 353 URLs con Modalidades Faltantes<br>260 Phishing (86.7%) / 93 Legítimas (31.0%)]
    end

    ITE --> CC
    ITE --> INC
```

### 2.1. Población Intention-To-Evaluate (ITE, $N=600$)
- **Definición:** Todas las URLs seleccionadas originalmente para el sondeo externo, independientemente de si los servidores respondieron, si los puertos estaban bloqueados o si la descarga de HTML falló.
- **Composición:** Exactamente 300 muestras maliciosas (URLhaus, PhishTank, OpenPhish) y 300 muestras benignas (Tranco, Majestic).
- **Justificación:** Representa el denominador real al que se enfrenta una pasarela o extensión de navegador en producción.

### 2.2. Población Complete-Case (CC, $N=247$)
- **Definición:** Subconjunto estricto de observaciones donde tanto el análisis de infraestructura ($M_1$) como la descarga y parseo del árbol DOM/HTML ($M_2$) concluyeron con estado `success`.
- **Composición:** **247 URLs** (40 phishing y 207 legítimas).
- **Advertencia Metodológica:** La prevalencia de phishing en el subconjunto complete-case cae del $50.0\%$ al **$16.19\%$**, debido a que el $86.67\%$ del phishing no sobrevive a la adquisición multimodal completa.

---

## 3. Estrategias Operativas Comparadas

Se evaluaron formalmente seis estrategias de decisión sobre el sondeo de 600 URLs:

1. **Estrategia A (Clasificación $M_2$ sobre Casos Completos):**  
   Aplica el modelo de contenido HTML $M_2$ exclusivamente sobre la población complete-case ($N=247$). Representa la práctica tradicional (y sesgada) de laboratorio.
2. **Estrategia B (Modelo Léxico $M_0$ Puro en ITE):**  
   Evalúa $M_0$ sobre el 100% de los 600 intentos. La cadena de texto de la URL está siempre disponible sin requerir peticiones de red. Cobertura: 100%.
3. **Estrategia C (Modelo $M_2$ con Respaldo / Fallback a $M_0$ ante Fallo):**  
   Intenta la adquisición multimodal completa. Si la adquisición de HTML y red es exitosa (caso completo), decide con $M_2$; si ocurre cualquier fallo de conexión, timeout o bloqueo sandbox, **activa el mecanismo de respaldo hacia la predicción léxica de $M_0$**. Cobertura: 100%.
4. **Estrategia D (Cascada Adaptativa con Fallback por Etapa — $M_4$):**  
   Aplica parada temprana simétrica ($H_{esc} = 0.15$). Si se requiere escalar a $M_1$ o $M_2$ pero la modalidad falla en red, la cascada utiliza la mejor evidencia previa disponible ($M_1$ o $M_0$) para emitir un veredicto forzado. Cobertura: 100%.
5. **Estrategia E (Cascada con Abstención Explícita ante Fallo — $M_5$):**  
   En lugar de forzar una predicción con un modelo previo cuando la modalidad escalada falla o la incertidumbre terminal persiste ($H > 0.50$), el sistema **se abstiene** (`abstained = 1`) y canaliza la URL a revisión humana (SOC). Se evalúan también los modos operativos *Fail-Closed* y *Fail-Open*.
6. **Estrategia F (Configuración con Imputación de Características / Vector de Ceros):**  
   Evalúa $M_2$ sobre los 600 casos completando los vectores con indicadores de ausencia (`infrastructure_available = 0.0`, `content_available = 0.0`) y ceros en las características faltantes.

---

## 4. Instrumentación y Telemetría de Adquisición

Para cada URL sondeada, la instrumentación registró de forma aislada y determinista en [`acquisition_attempts.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/03_missing_modalities/acquisition_attempts.csv):
- Identificador y metadatos: `cohort2_id`, `url`, `registered_domain`, `label`, `source`.
- Estado DNS: `resolved`, `dns_empty` (takedown), `blocked_sandbox_port`, `timeout`.
- Estado TLS: `established_TLSv1.3`, `established_TLSv1.2`, `https_failed_or_blocked`, `plain_http_no_tls`.
- Estado HTTP: `success_html_received`, `non_html_payload`, `connection_refused_or_host_unreachable`, `http_403`, `http_404`, `http_499`.
- Tiempos de respuesta: `time_dns_ms`, `time_request_ms`, `time_dom_ms`, `total_time_ms`.
- Disponibilidad: `html_available`, `visual_available`, `complete_case`.
- Banderas de decisión: `fallback_used`, `abstained`, `classification_result`.

---

## 5. Protocolo de Seguridad y Contención Experimental

En estricto cumplimiento de las normas de seguridad de ciberseguridad:
1. **Aislamiento de Red:** Todas las peticiones fueron ejecutadas desde entornos controlados en sandbox sin credenciales activas ni sesiones personales abiertas.
2. **Filtrado de Puertos Salientes:** La política del analizador bloqueó puertos arbitrarios comúnmente abusados por botnets (e.g., `:45209`, `:38636`, `:2003`), evitando participar en tráfico sospechoso.
3. **Prevención de SSRF:** Se bloquearon automáticamente direcciones de loopback (`127.0.0.1`), rangos privados RFC 1918 (`10.0.0.0/8`, `192.168.0.0/16`) y metadatos de computación en la nube (`169.254.169.254`).
4. **Modo Solo Lectura:** El cliente HTTP deshabilitó el envío de formularios, el seguimiento de descargas de ejecutables maliciosos y la ejecución de scripts no confinados.

---

## 6. Pruebas Estadísticas del Mecanismo de Faltantes (Rubin Taxonomy)

Para determinar formalmente la naturaleza estadística de la falta de datos:
- Se formuló la hipótesis nula $H_0$: *Los datos faltantes son Missing Completely at Random (MCAR), es decir, la probabilidad de fallo es independiente de si el sitio es phishing o legítimo.*
- Se aplicaron la **Prueba Exacta de Fisher** y la **Prueba de Independencia de Chi-Cuadrado ($\chi^2$)** sobre la tabla de contingencia $2 \times 2$ (Clase vs Estado de Adquisición).
- Se calculó la **Razón de Momios (*Odds Ratio*)** de missingness entre clases:
  $$\text{Odds Ratio} = \frac{\text{Missing}_{\text{phish}} \times \text{Complete}_{\text{legit}}}{\text{Complete}_{\text{phish}} \times \text{Missing}_{\text{legit}}}$$
- Se estimaron los intervalos de confianza del 95% para todas las métricas mediante **$B=1,000$ remuestreos bootstrap no paramétricos**.
