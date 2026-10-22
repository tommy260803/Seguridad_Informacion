# Informe de Limitaciones Científicas y Metodológicas
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Transparencia Científica — Fase 1: Validación Externa*

---

## 1. Alcance y Naturaleza de las Limitaciones

La investigación rigurosa en detección de phishing enfrenta desafíos metodológicos intrínsecos derivados de la volatilidad del ecosistema malicioso, las limitaciones de telemetría y las restricciones de reproducibilidad retrospectiva. En cumplimiento con los estándares editoriales de *Revista Politécnica*, este documento explicita todas las restricciones, factores de atrición y supuestos de los experimentos de validación externa.

---

## 2. Inventario de Limitaciones Específicas

### 2.1. Atrición Temporal y Vida Media de Sitios de Phishing (*Ephemeral Phishing*)
- **Fenómeno:** La literatura especializada documenta que la vida media de una campaña de phishing de credenciales oscila entre 4 y 36 horas antes de ser suspendida por registradores, bloqueada por Cloudflare/Google Safe Browsing o desmontada por el atacante.
- **Impacto Metodológico:** En una evaluación retrospectiva como la de la Cohorte Externa, la inmensa mayoría de las URLs maliciosas se encuentran inactivas en la actualidad.
- **Consecuencia en los Modelos Evaluables:** No es factible ejecutar los clasificadores multimodales avanzados ($M_1$ basado en HTML/DOM y $M_2$ basado en capturas visuales de pantalla y YOLOv8) sobre la Cohorte C, ya que estas etapas requieren la renderización activa del DOM o la captura de pantalla por Chrome DevTools Protocol (CDP). Por consiguiente, la validación externa se concentró estrictamente en los modelos que operan sobre la URL y metadatos de reputación ($M_0$ Léxico y `HybridM0Model`).

### 2.2. Dependencias de Red en Reglas Heurísticas Fuera de Línea
- **Fenómeno:** El módulo `DetectionRules` implementa reglas de alta señal que consultan servidores WHOIS (puerto 43) y geolocalización IP mediante sockets de red.
- **Impacto en Benchmark:** Al evaluar dominios que ya no resuelven o en entornos de prueba con restricciones de red o aislamiento, estas llamadas generan excepciones de tiempo de espera (`socket timed out` o `getaddrinfo failed`).
- **Manejo en la Implementación:** El código de PhishPe captura estas excepciones de forma defensiva y asigna un valor neutral (`triggered = False`), permitiendo que el pipeline concluya sin errores fatales. Sin embargo, en un despliegue en producción con caché local y DNS activo, algunas de estas reglas podrían aportar señales adicionales no cuantificadas en este benchmark fuera de línea.

### 2.3. Prevalencia de Laboratorio vs. Tasa Base Operacional Real
- **Fenómeno:** La Cohorte C fue construida deliberadamente con una prevalencia balanceada del 50.0% (600 phishing vs 600 legítimas) para mantener la comparabilidad directa contra la cohorte histórica ($N=1,200$).
- **Impacto en Métricas:** En el tráfico real de navegación de un usuario o una red corporativa, la prevalencia de phishing es extremadamente baja (típicamente $\ll 1\%$). Bajo el Teorema de Bayes, una tasa base baja comprime el valor predictivo positivo incluso para modelos con alta especificidad.
- **Recomendación Editorial:** En el manuscrito debe enfatizarse que la métrica de diseño más crítica para la viabilidad operativa es la tasa de falsos positivos ($\text{FPR} = 0.83\%$), ya que un FPR elevado saturaría al usuario con falsas alarmas e induciría fatiga de alertas.

### 2.4. Rutas Benignas Institucionales Curadas
- **Fenómeno:** Para superar el atajo de los dominios bare de Tranco y Majestic, las muestras legítimas de CISA `.gov` e instituciones universitarias HIPO `.edu` se enriquecieron con rutas de navegación representativas (`/portal/login`, `/services`, `/departments`, `/contact`).
- **Impacto:** Si bien estas rutas replican fielmente la estructura de directorios y formularios de portales públicos reales, no provienen de un registro pasivo de tráfico de clics de usuarios (*clickstream*). Constituyen una aproximación sintéticamente controlada para someter al modelo a variabilidad estructural profunda.

### 2.5. Ausencia de Clasificador de Abstención ($M_4$) en la Evaluación Externa
- **Fenómeno:** El clasificador $M_4$ está diseñado para abstenerse y solicitar revisión humana o telemetría multimodal cuando la incertidumbre es elevada.
- **Impacto:** Al evaluar la cohorte externa bajo decisiones forzadas binarias ($0$ o $1$), las muestras limítrofes son contabilizadas obligatoriamente como acierto o error, sin poder beneficiarse de la zona de abstención.

---

## 3. Matriz de Riesgos Metodológicos y Estrategias de Mitigación

| Riesgo Metodológico | Gravedad | Impacto en el Artículo | Estrategia de Mitigación Aplicada |
| :--- | :---: | :--- | :--- |
| Sobreestimación por malware | **CRÍTICA** | Falso recall elevado en versiones previas. | Exclusión total de URLhaus y sustitución por PhishTank con target verificado. |
| Falsos positivos por rutas | **ALTA** | El modelo falla en sitios web complejos. | Incorporación de 300 muestras institucionales con rutas profundas y reporte del FPR por subgrupo. |
| Fuga de información | **CRÍTICA** | Invalidez de las métricas de prueba. | Auditoría automatizada de solapamiento de dominios contra `samples.csv` (0% solapamiento verificado). |
| Comparaciones causales inválidas | **MEDIA** | Confusión entre cambios de prevalencia y efectividad del modelo. | Análisis de sensibilidad formal advirtiendo el cambio de prevalencia entre Cohorte A y B. |
