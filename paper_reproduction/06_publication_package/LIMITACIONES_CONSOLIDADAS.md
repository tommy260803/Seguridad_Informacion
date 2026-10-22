# Limitaciones Científicas, Metodológicas y Operativas Consolidadas
**Sistema:** PhishPe / PhishGuard Pro  
**Destino:** Paquete de Evidencias Científicas para *Revista Politécnica* (Ecuador)  
**Fecha:** Octubre 2026  

---

## 1. Introducción

La honestidad científica y el reporte riguroso de limitaciones son pilares fundamentales para la credibilidad académica de una publicación en ingeniería y ciberseguridad. En esta sección se consolidan formalmente todas las restricciones muestrales, supuestos de modelado, sesgos inherentes a los datos y barreras operativas identificadas a lo largo de las seis fases de auditoría científica del sistema PhishPe.

Estas limitaciones deben ser reconocidas explícitamente en la sección de discusión del manuscrito y consideradas al extrapolar los resultados a entornos de despliegue industrial.

---

## 2. Limitaciones Muestrales y Validez Externa

### 2.1. Tamaño y Ventana Temporal de la Cohorte Externa ($N=1,200$)
- **Restricción:** Aunque la cohorte externa de $N=1,200$ URLs ofrece un poder estadístico robusto para detectar diferencias de magnitud media ($\Delta F_1 \ge 0.02$) con $\alpha = 0.05$ y $1-\beta = 0.80$, su recolección se concentró en una ventana temporal acotada.
- **Implicación:** La ecología del phishing evoluciona rápidamente. Nuevas campañas con técnicas de ofuscación de URL recientemente descubiertas o dominios generados mediante nuevos algoritmos DGA podrían exhibir tasas de detección inferiores a las reportadas si no se reentrena periódicamente el extractor léxico.

### 2.2. Sesgo Estructural en Muestras Legítimas (Tranco y Majestic)
- **Restricción:** Las 600 URLs benignas de la cohorte externa provienen de los rankings de popularidad Tranco y Majestic Million.
- **Implicación:** Los sitios web de alta popularidad tienen perfiles de infraestructura muy estables (certificados SSL de autoridades certificadoras comerciales consolidadas, TTLs de DNS prolongados, registros WHOIS históricos extensos). En el tráfico real de un navegador web, los usuarios también acceden a sitios benignos pequeños, blogs personales o comercios electrónicos locales recién creados, los cuales comparten características de infraestructura (antigüedad de dominio baja, certificados gratuitos Let's Encrypt) con sitios maliciosos. Esto puede incrementar la tasa de falsos positivos en producción por encima del $0.6\%$ medido en $M_1$.

### 2.3. Representatividad Geográfica e Idiomática
- **Restricción:** Las fuentes de inteligencia de amenazas abiertas (PhishTank, OpenPhish) presentan un sesgo preponderante hacia marcas globales (banca estadounidense, servicios en la nube de EE.UU., gigantes tecnológicos).
- **Implicación:** Si bien el sistema incluye muestras orientadas a entidades ecuatorianas y latinoamericanas, la cobertura contra ataques de phishing dirigidos hiperlocales (e.g., cooperativas de ahorro y crédito regionales, portales municipales) depende fuertemente de la presencia de léxico regional en el conjunto de entrenamiento.

---

## 3. Limitaciones Metodológicas y de Datos Faltantes (MNAR)

### 3.1. Sesgo de Supervivencia y Asociación de Disponibilidad (Consistente con MNAR)
- **Hallazgo Crítico:** La auditoría del sondeo en vivo de $N=600$ evidenció una asociación empírica extrema entre la clase del sitio web y la disponibilidad de modalidades tardías (Fisher Exact Test $p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$). Si bien esto no constituye una prueba matemática formal del mecanismo no observado en el sentido estricto de Rubin, aporta evidencia empírica concluyente de un severo sesgo de supervivencia consistente con un comportamiento de datos faltantes no aleatorios (MNAR).
- **Implicación Metodológica:**
  - El $86.7\%$ de los sitios de phishing ya estaban dados de baja (HTTP 404, 503, NXDOMAIN, Connection Refused) en el momento del sondeo.
  - En consecuencia, evaluar un clasificador multimodal únicamente sobre el subconjunto de "casos completos" ($N=247$) genera un sesgo de selección severo (sesgo de supervivencia), sobreestimando la utilidad práctica de las modalidades tardías.
  - El modelo $M_2$ (HTML) y $M_3$ (Visual) simplemente **no están disponibles para el 86.7% de los ataques reales**, forzando al sistema a depender de mecanismos de contingencia (fallback a $M_0$).

### 3.2. Falla Crítica de la Imputación por Ceros (Estrategia B)
- **Riesgo Identificado:** Reemplazar vectores ausentes por ceros vectoriales en $M_2$ colapsa la especificidad del sistema, disparando la tasa de falsos positivos al $18.67\%$ y degradando la precisión a $76.24\%$.
- **Recomendación Obligatoria:** En sistemas de producción está terminantemente prohibido imputar valores cero en modelos multimodales concatenados sin re-entrenamiento adaptativo. Debe aplicarse la política de fallback jerárquico (Estrategia C: fallback a $M_0$), la cual preserva una precisión del $93.64\%$.

---

## 4. Limitaciones de Rendimiento y Arquitectura de Sistemas

### 4.1. Inviabilidad de Chrome CDP ($M_3$) en el Camino Crítico del Cliente
- **Sobrecosto de Latencia:** La captura y renderizado de capturas de pantalla mediante Chrome DevTools Protocol (CDP) requiere un tiempo medio de $2,166 \text{ ms}$ (con percentil 95 en $3,584 \text{ ms}$ y pico de $8,700 \text{ ms}$).
- **Sobrecosto de Recursos:** Ejecutar un navegador headless (`puppeteer` / `playwright` / Chromium) para capturas visuales en el dispositivo del usuario o en el servidor backend incrementa drásticamente el consumo de memoria RAM (> 250 MB por instancia de pestaña) y eleva la temperatura y uso de CPU.
- **Conclusión de Arquitectura:** La modalidad visual $M_3$ no es viable como clasificador primario en tiempo real para la navegación web interactiva. Su uso debe quedar estrictamente restringido a una función de verificación asíncrona fuera de banda o activada bajo solicitud explícita cuando el clasificador de abstención ($M_5$) señale incertidumbre severa sobre marcas de alto valor.

### 4.2. Latencia Externa No Controlada en Consultas de Infraestructura ($M_1$)
- **Variabilidad de Red:** Mientras que el análisis léxico ($M_0$) opera de manera totalmente determinista y offline en $0.18 \text{ ms}$, la extracción de características de infraestructura ($M_1$) depende de consultas DNS remotas, resolución WHOIS y negociación de handshakes SSL/TLS, demandando una media de $375 \text{ ms}$.
- **Riesgo:** Si los servidores DNS autoritativos o servidores WHOIS presentan congestión o bloqueo de tasa (rate-limiting), la latencia de $M_1$ puede degradarse hasta timeouts de $3,000 - 5,000 \text{ ms}$, requiriendo mecanismos estrictos de timeout y fallback inmediato a $M_0$.

---

## 5. Limitaciones de Seguridad y Evasión Adversarial

### 5.1. Evasión en Dominios de Alta Reputación (Evasión Temprana)
- **Vulnerabilidad de Cascada Naive:** Las políticas simétricas de salida temprana (e.g., salir como benigno si la probabilidad de phishing en $M_0$ es $< 0.10$) fallan ante ataques de phishing alojados en plataformas legítimas compartidas (Google Sites, Firebase Appspot, Canva, Microsoft SharePoint, Cloudflare Workers). En estas URLs, la estructura léxica imita dominios corporativos limpios, lo que provocó 13 falsos negativos en la evaluación histórica.
- **Mitigación y su Límite:** La implementación de la **Guarda Asimétrica** (exigir $p_0 \le 0.005$ para salida benigna) redujo exitosamente los falsos negativos de 25 a 22 (rescatando 3 ataques evasivos), forzando la inspección de infraestructura. No obstante, si el atacante compromete legítimamente un servidor institucional bien configurado con SSL y DNS antiguo, el sistema requerirá obligatoriamente el análisis de contenido HTML ($M_2$) para desambiguar el ataque.

### 5.2. Deriva de Conceptos (Concept Drift) y Ataques Adversariales Léxicos
- **Ataques de Homoglifos y Ofuscación:** Técnicas avanzadas de typosquatting con caracteres Unicode (ataques IDN punycode) o encadenamiento múltiple de subdominios dinámicos pueden burlar parcialmente los extractores de n-gramas léxicos de $M_0$ si no se cuenta con normalización fonética y de caracteres previa.

---

## 6. Síntesis para el Manuscrito Académico

El siguiente cuadro resumen condensa las limitaciones que deben ser citadas en el artículo para Revista Politécnica:

| Dimensión | Limitación Identificada | Impacto Medido | Mitigación Implementada |
|:---|:---|:---:|:---|
| **Disponibilidad** | Sitios de phishing caídos en vivo (patrón MNAR) | 86.7% sin HTML/Visual | Fallback jerárquico a $M_0$ (Estrategia C, Precisión 93.64%) |
| **Latencia** | Sobrecosto de renderizado Chrome CDP ($M_3$) | $+2,166 \text{ ms}$ latencia | Exclusión de $M_3$ del camino síncrono en tiempo real |
| **Falsos Negativos** | Phishing en plataformas de reputación (Firebase, etc.) | 13 FNs tempranos en cascada naive | Guarda Asimétrica ($p_0 \le 0.005$ para salida benigna; FN cae a 22) |
| **Imputación** | Colapso por imputación ingenua de ceros en $M_2$ | FPR salta de 0.6% a 18.67% | Prohibición de imputación; uso de fallback estructural |
| **Generalización** | Muestras benignas extraídas de Tranco/Majestic | Menor cobertura de dominios nuevos | Reentrenamiento planificado con tráfico mixto en producción |
| **Tiempo DNS/SSL** | Dependencia de red externa para $M_1$ | $\sim 375 \text{ ms}$ media | Timeouts estrictos configurables y caché local DNS |
