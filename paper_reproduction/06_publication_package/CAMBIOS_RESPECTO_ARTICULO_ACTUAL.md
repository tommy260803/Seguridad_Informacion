# Guía de Modificaciones Críticas: Cambios Respecto al Artículo Actual
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Correcciones Científicas y Metodológicas para el Autor/Redactor*

---

## 1. Justificación y Propósito del Documento

Durante las auditorías de reproducibilidad y los experimentos de las Fases 0 a 5, se identificaron discrepancias significativas entre las afirmaciones del borrador previo del artículo y la evidencia experimental real verificable del código y los datos.

Este documento enumera los **seis cambios obligatorios** que el redactor debe implementar para que el artículo cumpla con los estándares de rigor de *Revista Politécnica*, evitando el rechazo editorial por afirmaciones insostenibles o artefactos metodológicos.

---

## 2. Inventario de Modificaciones Críticas Obligatorias

### 1. Eliminación de Fórmulas Sintéticas de Latencia ($M_2$ y $M_3$)
- **Estado en el Borrador Previo:** Se utilizaba una fórmula sintética para estimar la latencia de $M_2$ (`max(12.0, content_bytes / 4500.0 + 18.0)`) y una constante fija de $+245.0 \text{ ms}$ añadida a imágenes estáticas de PIL para simular la captura de $M_3$.
- **Corrección Auditada:** Dichas fórmulas fueron erradicadas en su totalidad. Las latencias de $M_2$ se midieron directamente sobre el parseo real del árbol DOM en 97 archivos HTML archivados ($8.90 \text{ ms}$ de mediana), y las latencias de $M_3$ se basan exclusivamente en las trazas 100% auténticas del protocolo Headless Chrome DevTools Protocol (CDP) sobre 83 URLs ($2,166.36 \text{ ms}$ de mediana).
- **Acción para el Redactor:** Actualizar la sección de Metodología y Resultados para eliminar cualquier mención a proxies sintéticos y citar la telemetría real de Chrome CDP.

### 2. Reclasificación de URLhaus y Ajuste de la Cohorte Externa ($N=1,200 \to N=800$)
- **Estado en el Borrador Previo:** Se presentaba a la cohorte externa de 1,200 URLs como "phishing confirmado", incluyendo 297 URLs de URLhaus.
- **Corrección Auditada:** URLhaus es un repositorio de distribución de malware (troyanos, droppers, botnets), no un feed de suplantación de identidad (phishing). El análisis de contenido de la Fase 1 demostró que 96 muestras eran cargas binarias directas (`.exe`, `.apk`) sin interfaces de inicio de sesión.
- **Acción para el Redactor:**
  - Diferenciar en la tabla de evaluación externa la cohorte histórica ($N=1,200$, donde M0 obtiene F1=0.7118 debido a falsos negativos en malware) de la cohorte limpia de phishing específico ($N=800$, PhishTank + OpenPhish vs Tranco + Majestic, donde M0 alcanza F1=0.8268).
  - Justificar el protocolo de etiquetado en la sección de Amenazas a la Validez.

### 3. Diferenciación Obligatoria entre Caso Completo ($N=247$) e Intención de Evaluar ($N=600$)
- **Estado en el Borrador Previo:** El sondeo operativo se reportaba como si los 600 sitios hubiesen proporcionado todas las modalidades sensoriales, o se reportaban solo las 247 URLs completas sin advertir el sesgo de supervivencia.
- **Corrección Auditada:** La pérdida de modalidades es Missing Not At Random (MNAR, $p = 4.28 \times 10^{-46}$, Odds Ratio = 14.47). En campo, el 86.67% de los sitios de phishing ya estaban caídos o bloqueados al momento del sondeo, sobreviviendo solo 40 ataques en el conjunto completo.
- **Acción para el Redactor:**
  - Reportar en paralelo ambas poblaciones: Caso Completo ($N=247$, donde M2 alcanza F1=0.8395 sobre los 40 sobrevivientes) e Intención de Evaluar ($N=600$, donde la Estrategia C de Fallback procesa el 100% de ataques reales con F1=0.8246 y precisión del 93.64%).
  - Señalar que el reporte exclusivo de casos completos induce a un sesgo de supervivencia letal que enmascara el 86.7% de los ataques reales.

### 4. Sustitución de la Cascada Simétrica por la Cascada Asimétrica (Mitigación de Falsos Negativos)
- **Estado en el Borrador Previo:** Se presentaba la Cascada Simétrica ($M_4$, $H \le 0.15$) como la arquitectura óptima definitiva, sin analizar la procedencia de los 25 falsos negativos observados en la prueba *host_unseen*.
- **Corrección Auditada:** El análisis forense de la Fase 2 demostró que 13 de los 25 falsos negativos ocurrieron antes de $M_2$ debido a ataques alojados en dominios reputados (e.g. `firebaseapp.com`) con URLs sintácticamente limpias, engañando a $M_0$. La Cascada Asimétrica (Política C), que exige $p_0 \le 0.005$ para la salida benigna, recupera 6 de estos ataques, reduciendo los falsos negativos a 19 y elevando el F1 a 0.9311.
- **Acción para el Redactor:** Presentar la Cascada Asimétrica como la propuesta superadora y calibrada del artículo, comparándola frente a la cascada simétrica original en el estudio de ablación.

### 5. Incorporación de la Prueba Formal de No-Inferioridad ($\delta = 0.02$)
- **Estado en el Borrador Previo:** Se afirmaba que la cascada "no pierde precisión frente a M2" basándose únicamente en la proximidad visual de los números (0.9222 vs 0.9315), sin soporte de inferencia formal.
- **Corrección Auditada:** Se diseñó y ejecutó una prueba formal de no-inferioridad por bootstrap pareado ($B=2,000$ réplicas) con un margen preestablecido de $\delta = 0.02$. La Cascada Asimétrica demostró estadísticamente ser no-inferior a $M_2$ ($\text{IC}_{97.5\% \text{ unilateral}} = -0.0085 > -0.0200$, $p < 0.001$).
- **Acción para el Redactor:** Incorporar el gráfico de Forest Plot ([`fig_non_inferiority_forest_plot.png`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/figures/fig_non_inferiority_forest_plot.png)) en la sección de discusión estadística.

### 6. Distinción entre Adquisiciones Lógicas Evitadas y Latencia de Pared Real
- **Estado en el Borrador Previo:** Se insinuaba que reducir el 75% de las etapas equivalía a hacer el sistema un 75% más rápido para el usuario final.
- **Corrección Auditada:** La etapa $M_1$ (red DNS/TLS) consume el 98.8% del tiempo de pared ($1,272 \text{ ms}$ de mediana). Evitar el parseo DOM ($M_2$) ahorra solo $8.9 \text{ ms}$ de CPU. El ahorro real de tiempo de pared de la cascada oscila entre el 31.4% (vs $M_2$) y el 71.8% (vs $M_3$).
- **Acción para el Redactor:** Expresar con exactitud técnica que el sistema *"evita el 75.8% de las adquisiciones de contenido HTML, logrando una reducción del 31.4% en la latencia de pared total frente al modelo multimodal completo"*.

---
*Fin del documento de cambios respecto al artículo actual — Paquete de Transferencia.*
