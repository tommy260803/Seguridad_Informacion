# PROPUESTA CIENTÍFICA UNIFICADA (FASE IV)

## Título Provisional Defendible

- **Español:** *PhishPe: Evaluación de la Generalización, la Disponibilidad Multimodal Asimétrica y la Adquisición Secuencial Selectiva en la Detección de Phishing*
- **Inglés:** *PhishPe: Evaluating Generalization, Asymmetric Multimodal Availability, and Selective Sequential Acquisition in Phishing Detection*

---

## Contraste de la Propuesta Inicial

> **Propuesta inicial planteada para contraste:**  
> *"La utilidad de la adquisición progresiva de evidencia en detección de phishing depende de la calidad predictiva de las modalidades, su disponibilidad y los costes de decisiones anticipadas; un estimador complejo de disponibilidad puede perjudicar las decisiones bajo desplazamiento de distribución".*

**Dictamen de contraste:** La formulación es **científicamente exacta y está respaldada al 100 % por la evidencia empírica del proyecto**, con una precisión conceptual importante que incorporamos en nuestra formulación definitiva: el estimador predictivo de disponibilidad ($\hat{\pi}_m(x_0)$, regresión logística calibrada sobre 9 variables léxicas) no falla por tener una arquitectura neuronal masiva, sino por **intentar inferir una propiedad operativa efímera del servidor y de la red (disponibilidad HTTP/DNS) a partir de correlaciones sintácticas de la URL ($x_0$) que son específicas de la fuente de recolección y se invierten bajo desplazamiento de distribución**, mientras que el estimador constante marginal ($A_2$) permanece robusto porque impone una cota estructural conservadora ($\bar{\pi}_{\text{html}}=0.427 < 0.6593$) que evita consultar una modalidad de bajo rendimiento marginal ($M_2$).

---

## 1. Problema Científico

Los detectores de phishing multimodales suelen evaluarse bajo tres supuestos implícitos que rara vez se cumplen simultáneamente en operación real: (i) que todas las modalidades (URL, infraestructura DNS/TLS y contenido HTML/DOM) están disponibles de forma determinista cuando se solicitan, (ii) que detener el análisis tempranamente en una cascada ahorra latencia sin degradar la seguridad, y (iii) que un $F_1$ elevado sobre casos completos o sobre muestras no abstenidas refleja fielmente la capacidad de generalización del sistema ante nuevas fuentes. En la práctica, las páginas de phishing son efímeras y bloquean o fallan en las consultas con mucha mayor frecuencia que los sitios legítimos, los errores tempranos de alta confianza en etapas ligeras impiden adquirir evidencia correctiva posterior, y tanto los clasificadores como los estimadores auxiliares pueden aprender atajos de procedencia que colapsan bajo cambio de distribución.

## 2. Vacío de Conocimiento

1. En la literatura de **detección multimodal de phishing** (Opara et al., 2020; Aljofey et al., 2022; Murhej & Nallasivan, 2025), las evaluaciones se restringen mayoritariamente a subconjuntos de casos completos (*Complete-Case*), sin cuantificar el sesgo *Missing-Not-At-Random* (MNAR) entre clases ni descomponer estadísticamente cuánto aporta realmente el contenido HTML una vez observada la infraestructura de red.
2. En la literatura de **adquisición activa y secuencial de características (AFA)** (Saar-Tsechansky et al., 2009; Shim et al., 2018; Ma et al., 2019; Li & Oliva, 2021; Covert et al., 2023; Rahbar et al., 2025), se asume un **oráculo determinista** ($\pi_m \equiv 1$ al pagar el coste $c_m$), ignorando entornos adversarios donde el canal de adquisición falle estocásticamente y donde predecir dicha disponibilidad está sujeto a cambio de dominio.
3. En la literatura de **clasificación selectiva y cascadas** (Chow, 1970; Geifman & El-Yaniv, 2017; Hendrickx et al., 2024), no se ha caracterizado cómo interactúan la salida temprana asimétrica, la abstención terminal y la descalibración del estimador de disponibilidad en detección de phishing web.

## 3. Pregunta Central de Investigación

> **¿Cómo condicionan la ganancia marginal entre modalidades, la disponibilidad estocástica asimétrica (MNAR), el diseño de parada temprana/abstención y el desplazamiento de distribución el compromiso entre coste de adquisición, cobertura y riesgo penalizado en un sistema secuencial de detección de phishing?**

## 4. Objetivo General

Evaluar empírica y metodológicamente los determinantes y límites de la detección secuencial y selectiva de phishing a través de la arquitectura **PhishPe** y su motor de adquisición adaptativa (**RAEA**), cuantificando el aporte incremental de las modalidades de infraestructura y contenido, la consolidación de falsos negativos tempranos, el sesgo de disponibilidad en vivo, el impacto de la procedencia de los datos y la estabilidad de los estimadores de disponibilidad frente a priores constantes bajo desplazamiento de distribución.

## 5. Hipótesis y Preguntas Verificables

- **P1 / H1 (Ganancia marginal multimodal y riesgo de salida temprana en casos completos, $N=691$):**  
  *Hipótesis:* La incorporación de señales de infraestructura ($M_1$) sobre características léxicas de URL ($M_0$) produce una mejora estadísticamente significativa en discriminación, mientras que la adición posterior de contenido HTML ($M_2$) ofrece un beneficio incremental reducido; asimismo, las cascadas de salida temprana simétrica concentran la mayoría de sus falsos negativos antes de alcanzar la etapa de contenido, lo cual puede mitigarse restringiendo asimétricamente las salidas benignas tempranas.
- **P2 / H2 (Sesgo MNAR de disponibilidad, procedencia y denominadores selectivos, $N=1,200$, $N=903$ y $N=600$):**  
  *Hipótesis:* En sondeos externos en vivo, la disponibilidad de modalidades completas no es independiente de la clase (siendo significativamente inferior en phishing que en sitios legítimos, MNAR), y las métricas aparentes de generalización y selectividad son altamente sensibles a la contaminación de fuentes (`URLhaus`), a artefactos sintácticos (`www.`) y al cambio de denominador en políticas con abstención.
- **P3 / H3 (Adquisición adaptativa sensible a coste/riesgo y límites del estimador de disponibilidad bajo cambio de distribución, $N=118$ y $N=240$):**  
  *Hipótesis:* Una política secuencial consciente del riesgo asimétrico ($\gamma=15.0$) y de la disponibilidad reduce significativamente el riesgo penalizado frente a clasificadores fijos sin abstención ($M_1$) y reduce el coste frente a una adquisición ciega que asume disponibilidad perfecta ($A_1$); sin embargo, bajo desplazamiento de distribución en una cohorte externa independiente ($N=240$), un estimador paramétrico de disponibilidad basado en características léxicas ($x_0$) sufre descalibración y es superado en coste y riesgo por un prior marginal constante ($A_2$).

## 6. Contribución Principal

Una **investigación experimental y metodológica unificada** que demuestra y cuantifica los límites reales de la adquisición progresiva y selectiva de evidencia en detección de phishing: probamos que (1) la infraestructura de red ($M_1$) captura casi toda la ganancia predictiva multimodal mientras el HTML ($M_2$) es estadísticamente marginal ($p=0.7905$), (2) el $52\%$ de los falsos negativos en cascada ocurre por salidas benignas prematuras antes del HTML, (3) la disponibilidad en vivo es severamente MNAR ($13.33\%$ en phishing vs. $69.00\%$ en legítimos, $p=4.28 \times 10^{-46}$), y (4) en políticas secuenciales sensibles al coste y al riesgo (RAEA), predecir la disponibilidad desde rasgos léxicos falla bajo cambio de distribución ($\text{ROC-AUC}=0.2856$), por lo que una política de dos etapas con guarda benigna asimétrica y prior de disponibilidad constante ($A_2$) o rechazo de Chow sobre infraestructura ($B_5$) resulta más eficiente y segura que escalar adaptativamente mediante estimadores descalibrados.

## 7. Contribuciones Secundarias

1. **Corrección de fugas de calibración y evaluación en igual denominador:** Demostración de la partición tripartita por dominio registrado ($D_{\text{train}}, D_{\text{cal}}, D_{\text{val\_eval}}$) para calibración isotónica libre de sesgo optimista ($F_1=0.8972$, $\text{Brier}=0.0692$) y protocolo de comparación selectiva sobre el subconjunto exacto de decisiones comunes.
2. **Auditoría forense de sesgos de procedencia e invariancia de representación:** Cuantificación del impacto de mezclar feeds de malware (`URLhaus`, 297 muestras) con phishing de credenciales y demostración del compromiso entre invariancia sintáctica al prefijo `www.` ($\text{FPR}: 100\% \to 5.33\%$ en pares controlados) y sensibilidad en cohortes externas ($p_{\text{Holm}}=0.001465$).
3. **Paquete de evidencia abierta con trazabilidad individual:** Disponibilidad de predicciones fila por fila, estados de adquisición por canal, tiempos instrumentados y pruebas estadísticas no paramétricas reproducibles.

## 8. Diferencia Respecto a Antecedentes

- Frente a **Aljofey et al. (2022)**, **Opara et al. (2020)** y **Murhej & Nallasivan (2025)**, no asumimos disponibilidad completa del HTML ni evaluamos únicamente casos completos: cuantificamos la caída MNAR en vivo y demostramos la no significación marginal de $M_2$ sobre $M_1$.
- Frente a **Marchal et al. (2017)**, **Lin et al. (2021)** y **Liu et al. (2022)**, descomponemos formalmente en qué etapa de la cascada se originan los falsos negativos y evaluamos el compromiso riesgo-cobertura frente a la regla óptima de Chow (1970).
- Frente a la literatura de **AFA** (**Saar-Tsechansky et al., 2009; Shim et al., 2018; Ma et al., 2019; Li & Oliva, 2021; Covert et al., 2023; Rahbar et al., 2025**), relajamos el supuesto de oráculo determinista ($\pi_m = 1$) e identificamos empíricamente el fallo de los estimadores supervisados de disponibilidad bajo cambio de distribución.
- Frente a **Arp et al. (2022)**, **Rashid et al. (2024)** y **Ahamed et al. (2026)**, extendemos el análisis de atajos y desplazamiento de distribución desde la clasificación estática de URLs hacia las políticas secuenciales multimodales y los estimadores de disponibilidad.

## 9. Alcance de Generalización

Las conclusiones metodológicas y estructurales del estudio son generalizables a **sistemas de detección de amenazas web en tiempo real o cuasi-real que operan bajo múltiples modalidades con costes y tasas de fallo asimétricas** (URL $\to$ DNS/TLS/RDAP $\to$ DOM/HTML). Los valores numéricos puntuales de $F_1$, coste y riesgo están condicionados a las fuentes evaluadas (PhishTank, OpenPhish, `cert_pl`, `phishing_army`, Tranco, Majestic, `.gov`, `.edu`), a la prevalencia de las cohortes experimentales y a la matriz de costes fijada ($\gamma=15.0, c_{\text{abs}}=0.35$).

## 10. Limitaciones Fundamentales

1. **Dependencia paramétrica de la matriz de costes y aproximación miope del VoI:** El comportamiento de RAEA y $A_2$ (en particular, el umbral crítico $\pi_{\text{html}} > 0.65934$) depende de los pesos fijados ($\gamma=15.0, c_{\text{abs}}=0.35, \lambda=0.25, \alpha_m \in \{0.25, 0.20\}$) y de la diferencia entre los costes internos del selector (`cost.py`) y los costes realizados del evaluador (`evaluate.py`).
2. **Falta de condicionamiento secuencial en el estimador de disponibilidad de HTML:** El estimador logístico $\hat{\pi}_{\text{html}}(x_0)$ utiliza solo variables de etapa 0 y no incorpora el fallo observado en la etapa previa de red (`network == error`), lo que explica $65$ de las $75$ consultas fallidas de HTML en la cohorte externa.
3. **Efimeridad irrepetible de recursos web en vivo:** Aunque las predicciones individuales a partir de las sondas capturadas son 100 % deterministas y reproducibles, repetir hoy las consultas DNS/HTTP sobre las mismas URLs produciría estados de disponibilidad distintos debido a la desaparición natural de los dominios de phishing.
4. **Prevalencia experimental frente a tráfico real:** Las cohortes externas ($50\%$ positivas en $N=1,200$, $N=600$ y $N=240$) permiten estimar sensibilidad, especificidad y riesgo condicional con potencia estadística, pero no representan la prevalencia base ($\ll 1\%$) del tráfico general de navegación de un usuario final.
