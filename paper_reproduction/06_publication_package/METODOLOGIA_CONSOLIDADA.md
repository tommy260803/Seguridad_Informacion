# Metodología Consolidada y Arquitectura Experimental
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Metodología de Referencia para la Actualización del Manuscrito*

---

## 1. Visión General de la Arquitectura PhishPe

PhishPe es un sistema de detección y mitigación de phishing web concebido bajo el paradigma de **clasificación adaptativa progresiva**, optimizado para balancear precisión predictiva y eficiencia temporal en navegadores cliente (Chrome Manifest V3) y pasarelas perimetrales.

El sistema se compone de cuatro niveles jerárquicos de clasificación ($M_0, M_1, M_2, M_3$), un orquestador de salida temprana basado en entropía de información ($M_4$), un mecanismo de abstención selectiva ($M_5$), y una política de degradación progresiva (*fallback*) ante contingencias de red.

```
                         FLUJO METODOLÓGICO Y ARQUITECTURA EXPERIMENTAL
                                        URL de Entrada
                                              │
                                     ┌────────▼────────┐
                                     │  Etapa M0 (URL) │
                                     │   Léxico Puro   │
                                     └────────┬────────┘
                         p0 <= 0.005          │          p0 >= 0.85
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                   │
             [Salida Temprana:                                   [Salida Temprana:
             Legítimo Seguro]                                    Phishing Confirmado]
              (11.3% tráfico)                                     (27.8% tráfico)
                    │                                                   │
                    └─────────────────────────┬─────────────────────────┘
                                              │ Incertidumbre (H > 0.15)
                                     ┌────────▼────────┐
                                     │ Etapa M1 (Red)  │
                                     │    DNS + TLS    │
                                     └────────┬────────┘
                         p1 <= 0.05           │          p1 >= 0.85
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                   │
             [Salida Temprana:                                   [Salida Temprana:
             Legítimo Verificado]                                Phishing Detectado]
              (26.2% tráfico)                                     (10.6% tráfico)
                    │                                                   │
                    └─────────────────────────┬─────────────────────────┘
                                              │ Incertidumbre (H > 0.15)
                                     ┌────────▼────────┐
                                     │ Etapa M2 (DOM)  │
                                     │   HTML Content  │
                                     └────────┬────────┘
                                              │
                         ┌────────────────────┴────────────────────┐
                         │                                         │
                 H(p2) <= 0.50                             H(p2) > 0.50
                         │                                         │
                 [Veredicto Final:                         [ABSTENCIÓN M5:
                Phishing o Benigno]                        Derivación al SOC]
                  (96.4% cobertura)                         (3.6% abstención)
```

---

## 2. Definición Metodológica de Modelos y Extracción de Características

### 2.1. Etapa $M_0$: Modelo Léxico Puro
- **Insumos:** 11 características léxicas sintácticas derivadas del analizador de URLs y la lista de sufijos públicos (`public_suffix_list.dat`): longitud de URL, entropía de Shannon de caracteres, conteo de puntos y delimitadores, ratio de dígitos a caracteres alfanuméricos, presencia de direcciones IP codificadas y palabras clave sensibles (`login`, `verify`, `account`). Vector de entrada: `n_features_in = 11`.
- **Clasificador:** LightGBM / Gradient Boosting calibrado con escalamiento isotónico.
- **Coste Computacional:** Exclusivamente CPU local (< 0.2 ms en Nivel A). Cero peticiones de red.

### 2.2. Etapa $M_1$: Modelo de Infraestructura de Red
- **Insumos:** 36 características vectorizadas (`n_features_in = 36`: 11 léxicas + 25 de red e infraestructura). Incorpora la resolución DNS autoritativa (conteo de registros A/AAAA, dispersión de subredes /24, presencia de IPv6) y la cadena de certificados TLS (emisor de autoridad certificadora, días de validez restantes, conteo de nombres alternativos SAN y correspondencia con el dominio).
- **Clasificador:** CalibratedClassifierCV supervisado.
- **Coste Computacional:** Requiere resolución DNS y conexión TCP/TLS (~375 ms de media en Nivel B). No descarga el cuerpo HTML.

### 2.3. Etapa $M_2$: Modelo Multimodal DOM y Contenido HTML
- **Insumos:** 62 características vectorizadas (`n_features_in = 62`: 36 de $M_1$ + 26 de contenido HTML). Analiza el árbol DOM extraído: formularios de ingreso de credenciales y contraseñas, ratio de enlaces externos que apuntan a dominios diferentes, presencia de iframes ocultos de dimensión nula, anclas vacías (`href="#"`), scripts externos no autenticados y discrepancias entre la acción del formulario y el dominio actual.
- **Clasificador:** CalibratedClassifierCV multimodal.
- **Coste Computacional:** Requiere transferir el cuerpo HTTP y parsear el DOM.

### 2.4. Etapa $M_3$: Verificación Visual y Captura en Navegador
- **Insumos:** 75 características vectorizadas (`n_features_in = 75`: 62 de $M_2$ + 13 visuales). Extraídas a partir de capturas de pantalla de página completa en resolución fija (1280x800) ejecutadas mediante Headless Chrome bajo Chrome DevTools Protocol (CDP): hash perceptual pHash, densidad de bordes Sobel, desviación de luminancia, ratio de píxeles saturados y coincidencia visual con marcas objetivo.
- **Coste Computacional:** Altamente costoso ($2,166 \text{ ms}$ de media de renderizado). Se reserva exclusivamente como verificador dirigido fuera de banda.

---

## 3. Políticas Adaptativas de Salida Temprana y Abstención

### 3.1. Criterio Informacional de Parada Temprana
La incertidumbre posterior en la etapa $k \in \{0, 1, 2\}$ con probabilidad de phishing $p_k \in [0, 1]$ se evalúa mediante la entropía binaria de Shannon:
$$H(p_k) = - p_k \log_2(p_k) - (1 - p_k) \log_2(1 - p_k)$$

En la cascada estándar, si $H(p_k) \le H_{esc} = 0.15$, la predicción se considera suficientemente certera y se detiene la evaluación, emitiendo el veredicto con el modelo actual.

### 3.2. Guardia Asimétrica en Salida Benigna (Política C)
Para neutralizar la evasión léxica producida por nombres de dominio legítimos comprometidos, la Política C impone una asimetría estricta en $M_0$:
- Salida benigna en $M_0$ permitida únicamente si $p_0 \le 0.005$ (seguridad extrema).
- Salida phishing en $M_0$ permitida si $p_0 \ge 0.85$ con $H(p_0) \le 0.15$.
- Todas las muestras en el intervalo intermedio $(0.005, 0.85)$ son escaladas obligatoriamente a $M_1$ para inspeccionar registros DNS y certificados TLS.
- En la partición de prueba ($N=691$), esta política rescata 3 falsos negativos críticos (reduciendo FN de 25 a 22, $\text{Recall}=0.8848$, $F_1=0.9311$).

### 3.3. Clasificación Selectiva con Rechazo ($M_5$, Política D)
Cuando una muestra alcanza la etapa $M_2$ pero su entropía permanece en la zona de incertidumbre ($H(p_2) > 0.50$, correspondiente a $p_2 \in [0.11, 0.89]$), el sistema se abstiene formalmente de emitir una etiqueta binaria forzada y delega el caso a una cola de triaje asistido en el SOC.

---

## 4. Protocolo de Validación Externa y Particiones

1. **Partición Independiente Host-Unseen ($N=691$):** Separación estricta de nombres de dominio registrados respecto a entrenamiento y validación ($N_{\text{phish}}=191, N_{\text{legit}}=500$). Garantiza ausencia total de filtración de dominios (*domain leakage*).
2. **Cohortes Externas de Validación ($N=1,200$):**
   - *Cohorte Externa Histórica ($N=1,200$):* Feed-based tradicional (260 PhishTank, 43 OpenPhish, 297 URLhaus malware, 389 Tranco, 211 Majestic).
   - *Cohorte Externa Auditada Phishing Limpio ($N=1,200$):* Phishing puro sin malware (557 PhishTank, 43 OpenPhish, 195 Tranco, 150 CISA .gov, 150 HIPO Universities .edu, 105 Majestic). 0% solapamiento de dominios con el conjunto de entrenamiento.
3. **Sondeo en Vivo de Disponibilidad Truncada ($N=600$ ITE / $N=247$ CC):** Evaluación bajo condiciones reales de degradación de red y ciclo de vida efímero del phishing, demostrando asociación empírica extrema entre clase y disponibilidad ($p = 4.28 \times 10^{-46}, \text{OR}=14.47$).

---
*Fin del documento de metodología consolidada — Paquete de Transferencia.*
