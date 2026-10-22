# Informe de Limitaciones Científicas y Metodológicas: Datos Faltantes, Sesgo de Supervivencia y Fallback Operativo
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Transparencia Científica — Fase 3: Disponibilidad de Modalidades y Evaluación Operativa*

---

## 1. Propósito y Alcance del Documento

La evaluación de sistemas de detección de phishing en entornos de laboratorio frecuentemente asume una disponibilidad ideal e incondicional de todas las modalidades sensoriales (URL léxica, infraestructura de red, árbol DOM HTML y renderizado visual). Sin embargo, en despliegues operativos reales sobre Internet, las tasas de disponibilidad se encuentran severamente truncadas por la naturaleza efímera del phishing, caídas de conectividad, mecanismos de evasión y políticas de contención en el cliente.

Este informe documenta formalmente las limitaciones metodológicas, amenazas a la validez y advertencias interpretativas que deben acompañar a los resultados de la **Fase 3: Datos Faltantes, Sesgo de Selección y Fallback Operativo**, garantizando el cumplimiento de los estándares de reproducibilidad e integridad editorial de *Revista Politécnica*.

---

## 2. Inventario de Amenazas a la Validez y Limitaciones Específicas

### 2.1. Sesgo de Supervivencia en Cohortes de Caso Completo (*Complete-Case Survivorship Bias*)
- **Manifestación Empírica:** En el sondeo de $N=600$ URLs operativas, únicamente 247 casos lograron adquisición completa de todas las modalidades ($N_{CC} = 247$). La tasa de supervivencia fue drásticamente asimétrica: solo el 13.33% de los sitios de phishing (40 de 300) sobrevivieron a la adquisición completa, frente al 69.00% de los sitios legítimos (207 de 300).
- **Mecanismo de Faltante No Aleatorio (MNAR):** La prueba exacta de Fisher confirmó una dependencia extrema entre la etiqueta de clase y la pérdida de datos ($p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$, $\chi^2 = 189.63$). La ausencia de datos **no ocurre al azar** (*Missing Not At Random*); el phishing presenta una propensión 14.5 veces mayor a perder modalidades de red y contenido.
- **Riesgo Metodológico:** Evaluar un modelo multimodal exclusivamente sobre el subconjunto de caso completo ($N_{CC}=247$) induce un sesgo de supervivencia letal:
  1. Altera artificialmente la prevalencia de phishing de la muestra (del 50.0% real de la cohorte al 16.19% en el subconjunto completo).
  2. Descarta al 86.67% de los ataques reales observados en campo.
  3. Proporciona una estimación espuria del desempeño operativo ($F_1 = 0.8101$ sobre 40 ataques supervivientes, ignorando 260 ataques no resueltos).
- **Directriz de Publicación:** Queda terminantemente prohibido presentar el desempeño sobre casos completos como representativo de la efectividad global del sistema. Todo análisis debe contrastarse obligatoriamente bajo el principio de Intención de Evaluar (*Intention-To-Evaluate*, ITE, $N=600$).

### 2.2. La Discrepancia entre Latencia de Red y Latencia Algorítmica de Inferencia
- **Fenómeno:** La latencia de cómputo de los modelos de aprendizaje automático en CPU local es despreciable:
  - Inferencia léxica $M_0$: $< 1 \text{ ms}$.
  - Inferencia de infraestructura $M_1$: $\approx 2 \text{ ms}$.
  - Inferencia multimodal DOM $M_2$: $\approx 5 \text{ ms}$.
- **Cuello de Botella Operativo:** La latencia total del pipeline está dominada en un 99.8% por el retardo de red de Internet y las políticas de timeout:
  - Resolución DNS autoritativa: $45 - 250 \text{ ms}$.
  - Handshake TLS / TCP: $80 - 400 \text{ ms}$.
  - Descarga HTTP y renderizado DOM: $400 - 3,500 \text{ ms}$.
  - Timeout por fallo o *blackhole*: $5,000 \text{ ms}$ (definido por el sandbox).
- **Consecuencia para Cascadas y Fallback:** Cuando un sitio no responde o experimenta degradación de red, el sistema incurre en el costo máximo de espera ($5.0 \text{ s}$) antes de que el mecanismo de fallback a $M_0$ pueda activarse. Esto demuestra que la cascada adaptativa con salida temprana optimista (Fase 2) es esencial para decidir sitios obvios *antes* de iniciar conexiones de red costosas.

### 2.3. Ciclo de Vida Efímero del Phishing (*Time-to-Live*) y Desfase de Adquisición
- **Mecanismo:** Las campañas de phishing contemporáneas presentan una vida media activa extremadamente corta, frecuentemente inferior a 4 a 24 horas, debido a:
  - Takedowns activos por registradores de dominio y CERTs.
  - Bloqueos a nivel de DNS resolutivo (e.g., Quad9, Cloudflare 1.1.1.2).
  - Rotación rápida de infraestructura por parte de los atacantes (*fast-flux DNS*).
- **Evidencia Empírica:** De las 260 muestras de phishing que no lograron completar las modalidades, 73 registraron fallo DNS directo (`dns_empty`), 124 sufrieron errores de conexión (`connection_error` / `read_timeout`), y 36 fueron abortadas por redirecciones anómalas o caídas de servidor.
- **Lección Científica:** La adquisición tardía de un feed de amenazas (e.g., horas después de su reporte inicial) garantiza que una fracción masiva de la cohorte maliciosa ya sea inalcanzable. Un clasificador multimodal dependiente de HTML es inherentemente incapaz de analizar sitios que ya han sido dados de baja, mientras que el modelo léxico $M_0$ puede emitir veredictos instantáneos basados exclusivamente en la estructura sintáctica de la URL.

### 2.4. La Falacia de Imputación: Ausencia de Evidencia no es Evidencia de Malicia
- **Peligro de la Imputación Cero / Naive (Estrategia F):** Cuando las características de red o HTML no están disponibles, un enfoque ingenuo es imputarlas como ceros o valores por defecto y forzar la predicción con $M_2$.
- **Impacto Comprobado:** La Estrategia F generó un colapso en la especificidad del sistema, disparando la Tasa de Falsos Positivos al **18.67%** (56 falsos positivos sobre 300 sitios legítimos), frente al **5.00%** de la Estrategia C (Fallback a $M_0$) y el **3.38%** de los casos completos.
- **Razón Causal:** Los clasificadores supervisados entrenados con vectores completos aprenden que valores nulos o la ausencia de ciertas cabeceras de seguridad corresponden a patrones atípicos frecuentemente presentes en servidores de ataque. Al evaluar un sitio legítimo que sufrió un timeout fortuito de red, el modelo imputado interpreta la falta de datos como un indicador anómalo, etiquetándolo falsamente como phishing.
- **Regla Arquitectural PhishPe:** Un error de conexión de red, un timeout HTTP o una indisponibilidad de servidor **nunca debe interpretarse como prueba afirmativa de phishing**. En ausencia de evidencia confirmada de contenido, la arquitectura debe degradar responsablemente a la evidencia léxica verificable ($M_0$) o abstenerse selectivamente ($M_5$).

### 2.5. Restricciones del Entorno de Contención y Sandbox
- **Filtros de Seguridad:** La adquisición operativa se ejecutó bajo un sandbox de contención con reglas estrictas:
  - Bloqueo de puertos no estándar (80, 443, 8080 permitidos; puertos de panel de control como 2082, 2083, 8888 o puertos efímeros bloqueados).
  - Aborto preventivo ante tipos MIME no HTML (rechazo de descargas binarias directas como `.exe`, `.apk`, `.zip`, `.pdf`).
- **Incidencia:** 77 URLs fueron abortadas por puerto no permitido (`disallowed_port`) y 96 por contenido no HTML (`non_html_content_type`), principalmente concentradas en URLhaus (fuente de distribución de malware).
- **Advertencia:** Si bien estas políticas son indispensables para proteger la infraestructura de prueba contra infecciones cruzadas, introducen un sesgo operativo: los sitios maliciosos que operan en puertos no estándar o distribuyen cargas binarias puras sin interfaz web caen fuera del alcance de los clasificadores basados en DOM, reforzando la necesidad de inspección léxica ($M_0$) y telemetría de red perimetral.

### 2.6. Representatividad y Prevalencia del Sondeo de 600 URLs
- **Prevalencia Artificial:** El sondeo histórico de 600 URLs fue balanceado intencionalmente al 50.0% (300 benignas, 300 maliciosas) con el objetivo de maximizar la potencia estadística para evaluar la precisión y recall de ambas clases.
- **Realidad Operativa:** En el tráfico web real de una organización o proveedor de servicios, la prevalencia de phishing se sitúa entre el 0.01% y el 0.5% (desbalance de clases severo de 1:1000 o más).
- **Implicación en Valor Predictivo:** Bajo una prevalencia real del 0.1%, incluso una tasa de falsos positivos del 5.0% (obtenida por la Estrategia C) generaría una saturación inmanejable de falsas alarmas. Para entornos de tráfico masivo no filtrado, es obligatorio:
  1. Operar con un umbral de decisión mucho más estricto ($p_{th} \ge 0.85$).
  2. Implementar listas blancas de dominios de alta confianza (e.g., Tranco Top 10k).
  3. Exigir la confirmación visual de marca antes de emitir bloqueos invasivos en el navegador.

---

## 3. Resumen de Recomendaciones para el Manuscrito

| Aspecto | Práctica Rechazada | Práctica Obligatoria en *Revista Politécnica* |
| :--- | :--- | :--- |
| **Población de Evaluación** | Reportar únicamente métricas sobre casos completos ($N=247$). | Reportar ambas poblaciones: Caso Completo ($N=247$) e Intención de Evaluar ($N=600$). |
| **Tratamiento de Faltantes** | Imputación estática con ceros forzando $M_2$ (Estrategia F). | Degradación progresiva con Fallback dinámico ($M_0$) o Clasificación Selectiva ($M_5$). |
| **Interpretación de Timeouts** | Asumir que un sitio caído es malicioso o catalogarlo como amenaza. | Clasificar estrictamente con la evidencia disponible sin imputaciones punitivas. |
| **Tiempo de Respuesta** | Promediar tiempos de inferencia algorítmica sin incluir red. | Reportar latencia de pared total distinguiendo red ($P_{50}, P_{95}$) de cómputo. |
| **Generalización** | Afirmar que el sistema alcanza $F_1 = 0.95$ en cualquier condición. | Explicar las condiciones de contención, filtros MIME y sensibilidad a la degradación de red. |

---
*Fin del documento de limitaciones — Fase 3: Datos Faltantes y Fallback Operativo.*
