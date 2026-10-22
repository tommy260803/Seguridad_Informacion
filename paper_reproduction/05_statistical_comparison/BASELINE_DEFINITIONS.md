# Definición Formal de Líneas Base (*Baselines*) de Comparación
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Especificación — Fase 5: Comparación Estadística y Estudios de Ablación*

---

## 1. Justificación de la Selección de Baselines

Para evaluar con rigor los avances arquitectónicos de PhishPe (cascadas adaptativas, salida temprana basada en entropía y clasificación selectiva con abstención), es metodológicamente imperativo compararlos frente a políticas y modelos de referencia sencillos y reproducibles.

Se definieron formalmente siete líneas base bajo protocolos de evaluación idénticos sobre la partición independiente *host_unseen* ($N=691$).

---

## 2. Catálogo Formal de Baselines

### 2.1. Baseline A: $M_0$ Fijo (Léxico Puro)
- **Definición:** Clasificador basado exclusivamente en características sintácticas y estadísticas de la URL (longitud, entropía de caracteres, conteo de delimitadores, palabras clave de seguridad y dominios de primer nivel).
- **Entrada:** Vector de 11 características (`AUTHORITY_FEATURE_NAMES`).
- **Umbral Operativo:** $\tau_0^* = 0.382667$ (optimizado en partición de validación).
- **Comportamiento:** Monolítico, 0 conexiones de red, coste $N_{\text{mod}} = 1.0$.
- **Propósito:** Cota inferior de coste y cota base de precisión sin telemetría de red.

### 2.2. Baseline B: $M_1$ Fijo (URL + Infraestructura de Red)
- **Definición:** Clasificador concatenado que incorpora resolución DNS autoritativa (conteo de IPs, dispersión /24, presencia de IPv6) y cadena de certificados TLS (días restantes, emisor, longitud de cadena).
- **Entrada:** Vector de 36 características (11 léxicas + 25 de infraestructura).
- **Umbral Operativo:** $\tau_1^* = 0.525014$.
- **Comportamiento:** Monolítico, ejecuta consultas DNS y conexión de red en el 100% de los casos. Cero descargas HTML ($N_{\text{mod}} = 2.0$).
- **Propósito:** Evaluar la ganancia neta aportada por la infraestructura antes de incurrir en la descarga de contenido web.

### 2.3. Baseline C: $M_2$ Completo (Monolítico DOM Multimodal)
- **Definición:** Clasificador multimodal completo que añade el parseo del árbol DOM HTML (formularios de contraseña, discrepancia de dominios en enlaces externos, presencia de iframes ocultos y anclas vacías).
- **Entrada:** Vector de 62 características (11 léxicas + 25 infra + 26 contenido HTML DOM).
- **Umbral Operativo:** $\tau_2^* = 0.394962$.
- **Comportamiento:** Monolítico sin parada temprana. Descarga y procesa HTML en el 100% de las URLs ($N_{\text{mod}} = 3.0$).
- **Propósito:** Cota superior teórica de rendimiento multimodal sin optimización de coste.

### 2.4. Baseline D: Cascada Original ($M_4$ Simétrica con Entropía de Shannon)
- **Definición:** Cascada adaptativa con escalamiento guiado por la entropía de Shannon $H(p_k) = -p_k \log_2 p_k - (1-p_k) \log_2(1-p_k)$.
- **Criterio de Parada Temprana:** Se detiene en la etapa $k \in \{0, 1\}$ si $H(p_k) \le H_{esc} = 0.15$ (lo que equivale aproximadamente a $p_k \le 0.023$ o $p_k \ge 0.977$). En caso contrario, escala a la siguiente etapa.
- **Comportamiento:** Dinámico, salida simétrica tanto para clase legítima como phishing.
- **Propósito:** Representa la implementación histórica del artículo para verificar su tasa real de ahorro de adquisiciones (75.83%) y evaluar su vulnerabilidad a la evasión léxica.

### 2.5. Baseline E: Cascada con Margen Lineal Simple (*Confidence Threshold*)
- **Definición:** Cascada progresiva que sustituye la entropía no lineal de Shannon por una regla heurística simple basada en el margen de confianza respecto a la incertidumbre máxima:
  $$\text{Salir en etapa } k \iff |p_k - 0.50| \ge \gamma = 0.40 \iff p_k \le 0.10 \lor p_k \ge 0.90$$
- **Comportamiento:** Regla de umbral simétrica sin funciones logarítmicas.
- **Propósito:** Desafiar científicamente la necesidad de la formulación informacional de Shannon; comprobar si una regla lineal intuitiva alcanza un compromiso equivalente.

### 2.6. Baseline F1: Cascada Asimétrica Optimizada (Política C)
- **Definición:** Cascada adaptativa que impone una restricción asimétrica estricta sobre la salida benigna temprana:
  - En $M_0$: Salida benigna permitida únicamente si $p_0 \le 0.005$ (seguridad extrema); salida phishing si $p_0 \ge 0.85$ con $H(p_0) \le 0.15$.
  - En $M_1$: Salida benigna si $p_1 \le 0.05$; salida phishing si $p_1 \ge 0.85$.
  - De lo contrario, escala obligatoriamente a $M_2$.
- **Propósito:** Eliminar los falsos negativos inducidos por ataques de phishing alojados en infraestructuras de confianza con URLs sintácticamente limpias.

### 2.7. Baseline F2: Cascada Selectiva con Abstención (Política D / $M_5$)
- **Definición:** Sistema de clasificación selectiva que incorpora un clasificador de rechazo cuando la incertidumbre en $M_2$ permanece elevada ($H(p_2) > 0.50 \iff p_2 \in [0.11, 0.89]$).
- **Comportamiento:** En lugar de forzar una etiqueta binaria dudosa, el sistema emite un veredicto formal de `ABSTAIN` y deriva la muestra a triaje forense humano (SOC).
- **Propósito:** Cuantificar el techo máximo de precisión alcanzable mediante abstención a costa de una reducción controlada de la cobertura autónoma.

---

## 3. Matriz Sinóptica de Líneas Base

| Identificador | Nombre Descriptivo | Modalidades | Criterio de Decisión | Parada Temprana | Abstención | Coste Medio ($N_{\text{mod}}$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline A** | $M_0$ Léxico Fijo | 1 | $p_0 \ge 0.3827$ | NO | NO | 1.000 |
| **Baseline B** | $M_1$ Infraestructura Fijo | 2 | $p_1 \ge 0.5250$ | NO | NO | 2.000 |
| **Baseline C** | $M_2$ Monolítico DOM | 3 | $p_2 \ge 0.3950$ | NO | NO | 3.000 |
| **Baseline D** | Cascada Original Simétrica | $1 \to 3$ | $H(p) \le 0.15$ | SÍ (Simétrica) | NO | 1.851 |
| **Baseline E** | Cascada Margen Simple | $1 \to 3$ | $|p - 0.5| \ge 0.40$ | SÍ (Lineal) | NO | 1.402 |
| **Baseline F1**| Cascada Asimétrica (Pol. C) | $1 \to 3$ | Asimétrico ($p_0 \le 0.005$) | SÍ (Asimétrica) | NO | 2.169 |
| **Baseline F2**| Cascada Selectiva (Pol. D) | $1 \to 3$ | Selectivo ($H_2 \le 0.50$) | SÍ | SÍ (3.62%) | 1.851 |

---
*Fin del documento de definición de baselines — Fase 5: Comparación Estadística y Ablaciones.*
