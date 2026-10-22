# AFIRMACIONES_CIENTIFICAS.md: Catálogo Epistemológico de Afirmaciones

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Criterio de Evaluación:** Estándar de rigor científico Scopus / IEEE / ACM.

---

## 1. Clasificación Rigurosa de Afirmaciones

### Afirmación 1: Reducción de Falsos Negativos Prematuros en $M0$
> *"La política RAEA-Phish reduce drásticamente las clasificaciones benignas erróneas emitidas en la etapa de URL frente a cascadas basadas puramente en incertidumbre."*
- **Clasificación:** **RESPALDADA**
- **Evidencia Empírica:** En el conjunto confirmatorio `test_eval` ($N=300$), la cascada de entropía simétrica (B3) emitió 12 falsos negativos prematuros en $M0$ (41.4% de sus fallos totales). RAEA-Phish redujo esta cifra a solo 3 falsos negativos en $M0$ (reducción del 75.0%), forzando la adquisición de evidencia de red correctiva.

### Afirmación 2: Superioridad en Pérdida Esperada Ponderada (Riesgo de Bayes)
> *"Al modelar explícitamente la asimetría de consecuencias de ciberseguridad ($\gamma = 15$), RAEA-Phish logra una pérdida ponderada estadísticamente inferior a cualquier clasificador fijo o cascada clásica."*
- **Clasificación:** **RESPALDADA**
- **Evidencia Empírica:** El riesgo ponderado medio de RAEA-Phish es $0.3867$ [95% CI: $0.2100 - 0.5967$], frente a $0.8588$ de la cascada de entropía B3 y $1.2300$ del modelo completo B2. En remuestreo bootstrap pareado ($B=2,000$), la reducción de riesgo fue positiva en el 100% de las réplicas ($p < 0.0001$ frente a todos los baselines B0 a B5).

### Afirmación 3: Ahorro Computacional y Eficiencia en Tiempo Real
> *"RAEA-Phish preserva una fracción sustancial del ahorro computacional de las cascadas adaptativas sin requerir la ejecución monolítica de todas las modalidades."*
- **Clasificación:** **RESPALDADA**
- **Evidencia Empírica:** RAEA-Phish requiere en promedio solo $2.02$ modalidades por URL (frente a 3.00 forzadas en M2) y una latencia mediana de $886.5\text{ ms}$ (frente a $1,971.2\text{ ms}$ en M2), lo que representa un ahorro del $65.2\%$ del coste computacional.

### Afirmación 4: Estimación Temprana de Disponibilidad desde Características Léxicas
> *"Es factible anticipar la viabilidad de conexión a la infraestructura y descarga del DOM utilizando únicamente el vector de autoridad léxico de la URL."*
- **Clasificación:** **RESPALDADA CON LIMITACIONES**
- **Evidencia Empírica:** El estimador de disponibilidad logró un ROC-AUC de $0.7388$ en infraestructura y $0.7986$ en contenido DOM en evaluación out-of-sample ($N=300$). No obstante, la precisión disminuye ante sitios de phishing alojados en CDNs o plataformas serverless legítimas, donde el fallo ocurre por eliminación del path o token y no por inaccesibilidad del dominio raíz.

### Afirmación 5: Generalización en Fuentes Externas Heterogéneas
> *"El comportamiento superior de RAEA-Phish se sostiene a través de múltiples fuentes externas de phishing y dominios benignos no observados durante el desarrollo."*
- **Clasificación:** **RESPALDADA CON LIMITACIONES**
- **Evidencia Empírica:** Validado en 7 fuentes independientes (CERT.pl, OpenPhish, PhishTank, URLhaus, CISA .gov, Majestic Million, Portales Universitarios). Sin embargo, en feeds dominados por malware binario directo (URLhaus), la ganancia sobre el modelo léxico es menor debido a la alta tasa de servidores apagados antes de la inspección.

### Afirmación 6: Reducción del Fraude Financiero o Robo de Credenciales en Usuarios Humanos
> *"El despliegue de RAEA-Phish previene el robo de credenciales en organizaciones."*
- **Clasificación:** **NO DEMOSTRADA / FUERA DEL ALCANCE**
- **Fundamento:** Esta investigación evalúa métricas algorítmicas de clasificación de URLs y sitios web. Medir la reducción de impacto humano requeriría estudios de campo con telemetría de endpoints y análisis de comportamiento de víctimas, lo cual excede el alcance formal declarado de este trabajo (Regla 13).
