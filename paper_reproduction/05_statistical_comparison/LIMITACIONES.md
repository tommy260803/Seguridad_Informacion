# Informe de Limitaciones Científicas y Amenazas a la Validez: Comparación Estadística y Ablaciones
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Transparencia Científica — Fase 5: Inferencia Estadística, Baselines y Estudios de Ablación*

---

## 1. Propósito y Alcance del Documento

Este documento formaliza las limitaciones metodológicas, los supuestos de las pruebas inferenciales y las amenazas a la validez externa identificadas durante la ejecución de la **Fase 5: Comparación Estadística, Baselines y Estudios de Ablación**, en estricto cumplimiento de los estándares de integridad editorial de *Revista Politécnica*.

---

## 2. Inventario de Amenazas a la Validez y Limitaciones Específicas

### 2.1. Sensibilidad a la Elección del Margen de No-Inferioridad ($\delta = 0.02$)
- **Definición del Margen:** Se seleccionó a priori un margen de no-inferioridad de $\delta = 0.02$ (2 puntos porcentuales de F1-score), justificándolo en base a que un sistema que ahorra el $75.8\%$ de las descargas HTML puede tolerar una discrepancia estadística máxima del $2\%$ sin comprometer la protección perimetral del usuario.
- **Riesgo Epistémico:** Si un analista u organización adoptara un margen clínico/industrial ultra-estricto de $\delta = 0.005$ (0.5% de F1), la Cascada Original ($M_4$) no superaría la prueba ($\text{IC}_{\text{low}} = -0.0234 \le -0.0050$), mientras que la Cascada Asimétrica ($M_4$ Asimétrica) requeriría un tamaño muestral significativamente mayor a $N=691$ para estrechar el intervalo de confianza por debajo de $\pm 0.005$.
- **Directriz para el Manuscrito:** En la publicación debe explicitarse con total transparencia que la no-inferioridad está demostrada bajo el margen específico $\delta = 0.02$.

### 2.2. Sensibilidad del Error de Calibración Esperado ($\text{ECE}$) a la Estrategia de Discretización
- **Condición de Prueba:** El análisis de calibración probabilística se calculó empleando $M = 10$ intervalos uniformes en $[0, 1]$.
- **Limitación Teórica:** La literatura reciente en Machine Learning (e.g., Nixon et al., 2019) señala que el estimador empírico de ECE con intervalos fijos es sensible al número de particiones y a la densidad de muestras en los extremos. Si bien la ordenación relativa de los modelos se mantiene ($M_0$ notablemente peor calibrado que $M_1$ y $M_2$), los valores absolutos de $\text{MCE}$ en intervalos con pocas observaciones deben interpretarse con cautela.

### 2.3. Cuello de Botella Operacional de la Clasificación Selectiva (Política D)
- **Compromiso Cobertura-Precisión:** La Política D alcanza un $F_1 = 0.9493$ y una precisión perfecta del $100.0\%$ eliminando por completo los falsos positivos ($\text{FPR} = 0.0\%$) al derivar 25 casos de alta entropía a abstención (tasa de rechazo del $3.62\%$).
- **Amenaza Práctica:** Aunque un $3.62\%$ es una cifra excelente para un clasificador selectivo, en un entorno de pasarela corporativa que procese $1,000,000$ de URLs diarias, esto generaría una cola de **$36,200$ transacciones diarias** para revisión humana por analistas del Centro de Operaciones de Seguridad (SOC). A menos que se disponga de un equipo forense dimensionado para tal volumen, las políticas automatizadas *Fail-Safe* (como la Cascada Asimétrica) son más viables en la práctica.

### 2.4. Representatividad de la Partición *Host-Unseen* ($N=691$)
- **Naturaleza de la Muestra:** La partición de prueba *host_unseen* fue diseñada para evaluar la capacidad de generalización sobre nombres de dominio nunca vistos durante el entrenamiento ($N_{\text{phish}}=191, N_{\text{legit}}=500$).
- **Límites de Generalización:**
  - Constituye una captura temporal estática. Si bien la separación estricta de dominios previene la fuga de información trivial (*domain leakage*), no evalúa longitudinalmente la deriva conceptual (*concept drift*) que ocurre a lo largo de meses ante la evolución de técnicas de evasión de atacantes.
  - La cohorte externa de validación de $N=1,200$ (Fase 1) complementa esta evaluación, pero se recomienda a futuro establecer observatorios continuos de telemetría.

### 2.5. Evasiones Dinámicas no Capturadas por el Árbol DOM Estático
- **Limitación del Modelo $M_2$:** Las características de contenido HTML se extraen de la respuesta HTTP estática. Ataques de phishing basados en frameworks JavaScript modernos (e.g., React, Angular) o que emplean técnicas de ofuscación dinámica (*client-side rendering*, ofuscación con WebSockets o generación diferida de formularios mediante eventos `mousemove`) escapan al análisis estático de BeautifulSoup / regex, reforzando la necesidad de que la infraestructura perimetral ($M_1$) y los módulos de detección homográfica operen en primera línea.

---

## 3. Resumen de Buenas Prácticas Metodológicas en la Publicación

| Práctica Rechazada | Práctica Obligatoria en el Manuscrito | Justificación Científica |
| :--- | :--- | :--- |
| **Afirmar no-inferioridad sin definir el margen a priori** | Declarar y justificar el margen $\delta = 0.02$ antes de reportar la prueba. | Cumplimiento del estándar internacional de pruebas de no-inferioridad (FDA / CONSORT). |
| **Ocultar la pérdida de cobertura en abstención** | Reportar simultáneamente precisión sobre decididos y tasa de abstención. | Transparencia total sobre el impacto operacional en el SOC. |
| **Afirmar que $M_0$ es suficiente para producción** | Reportar la descalibración de $M_0$ ($\text{ECE}=0.086$) y sus 25 falsos negativos. | Justifica la necesidad de la cascada y la inspección de infraestructura. |
| **Afirmar significancia estadística sin corrección múltiple** | Aplicar Benjamini-Hochberg FDR y Bonferroni sobre la familia de tests. | Control riguroso de falsos descubrimientos estadísticos. |

---
*Fin del documento de limitaciones — Fase 5: Comparación Estadística y Estudios de Ablación.*
