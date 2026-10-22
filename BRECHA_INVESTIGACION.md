# BRECHA_INVESTIGACION.md: Brecha de Investigación y Justificación Científica

**Título:** Adquisición Adaptativa de Evidencia Consciente de Riesgo y Disponibilidad en Detección de Phishing Web  
**Método:** RAEA-Phish  

---

## 1. La Brecha Científica Fundamental

A pesar de la extensa literatura en detección automatizada de phishing web y en aprendizaje activo de características (*active feature acquisition*), existe una desconexión crítica entre los supuestos teóricos de los modelos secuenciales y la realidad operativa de la ciberseguridad en la web:

> **La paradoja de la disponibilidad y el riesgo en phishing:**  
> Los sitios web maliciosos son altamente efímeros (vida media inferior a 24-48 horas), suelen alojarse en infraestructuras volátiles y emplean activamente técnicas de camuflaje (*cloaking*) o evasión léxica. Al mismo tiempo, el impacto de una brecha de seguridad (Falso Negativo) supera en órdenes de magnitud la molestia de una verificación profunda (Falso Positivo).

Los sistemas actuales adolecen de tres limitaciones interconectadas que constituyen la brecha de investigación abordada:

---

## 2. Los Tres Problemas Específicos

### Problema 1: Salidas Benignas Prematuras por Atajos de Aprendizaje (*Shortcut Learning*)
- **Manifestación:** Los clasificadores basados únicamente en URL ($M0$) aprenden patrones estadísticos (longitud de URL, presencia de subdominios, tokens léxicos). Cuando los atacantes utilizan técnicas como:
  - URLs cortas y limpias en servicios de acortamiento (`bit.ly`, `tinyurl.com`),
  - Dominios legítimos comprometidos o servicios de hosting compartido (`sharepoint`, `pages.dev`, `firebaseapp.com`),
  - Ataques homógrafos con normalización inconsistente o nombres de dominio de aspecto estándar,
  el modelo $M0$ emite una probabilidad de phishing cercana a cero ($p_{M0} < 0.02$).
- **Falla de la Cascada Convencional:** Al tener $p_{M0}$ extremo, la entropía de Shannon es muy baja ($H(p_0) \le 0.15$). La cascada estándar interpreta erróneamente esta certeza estadística como una prueba concluyente de legitimidad y **se detiene**, emitiendo un veredicto de "legítimo".
- **Consecuencia:** Se produce un **Falso Negativo Silencioso**. La evidencia crucial que habría descubierto el phishing (un certificado TLS recién emitido por Let's Encrypt para un dominio no correlacionado, o un formulario que envía credenciales a un servidor externo) **nunca llega a ser consultada**.

### Problema 2: Ceguera ante la Indisponibilidad de Modalidades y Desperdicio Operativo
- **Manifestación:** En la web viva, una proporción sustancial de sitios de phishing ya ha sido mitigada, suspendida por el registrador o bloqueada por listas de reputación DNS al momento de ser inspeccionada.
- **Evidencia empírica en Cohorte 2:** De 300 URLs de phishing analizadas en tiempo real, el 48.0% presentó fallos o bloqueos a nivel de red (DNS/TLS) y el 85.3% falló en la descarga o parseo del contenido HTML.
- **Falla de los Métodos Previos:** Las arquitecturas existentes asumen disponibilidad determinista de las modalidades. Al solicitar "contenido DOM" o "renderizado visual" de un sitio inaccesible, el sistema consume timeouts de conexión (5 a 20 segundos por intento), consumiendo hilos de ejecución y degradando severamente el throughput del gateway de seguridad.
- **Oportunidad no explorada:** Es posible estimar la probabilidad de éxito de adquisición de red o contenido utilizando señales léxicas de la URL (presencia de IP directa, acortador, TLD exótico, longitud anormal).

### Problema 3: Desalineación entre Métricas Estadísticas Simétricas y Costes Operativos Reales
- **Manifestación:** Los algoritmos de clasificación multietapa optimizan métricas simétricas globales (Accuracy, Entropía de Shannon, F1 estándar con umbral $0.5$).
- **Falla:** En la práctica operativa de un Security Operations Center (SOC) o un navegador empresarial:
  $$\text{Coste}(FN) \gg \text{Coste}(FP)$$
  Un modelo que intercambia 5 Falsos Positivos para eliminar 1 Falso Negativo crítico proporciona un beneficio neto masivo para la seguridad de la organización. La política de adquisición de evidencia debe estar guiada explícitamente por una función de riesgo esperado que internalice esta asimetría.

---

## 3. Formulación del Vacío de Conocimiento

Ninguna investigación previa ha propuesto una política de adquisición adaptativa multietapa para detección de phishing que:
1. Pondere la ganancia esperada de información mediante el **riesgo asimétrico de Bayes** ($C_{FN} / C_{FP}$),
2. Modele la **disponibilidad esperada de cada modalidad** como un factor de descuento probabilístico sobre el coste de adquisición, y
3. Proporcione **garantías formales contra la salida benigna prematura** ante incertidumbre léxica residual.

Este vacío de conocimiento es el que **RAEA-Phish** cubre de forma analítica, experimental y reproducible.
