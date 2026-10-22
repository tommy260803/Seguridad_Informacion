# Guía Editorial: Afirmaciones Permitidas, con Limitaciones y Prohibidas
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Control Epistémico para el Asistente Redactor del Manuscrito*

---

## 1. Propósito y Reglas de Uso para el Redactor

Este documento establece las directrices editoriales estrictas que **deben guiar la redacción o actualización del manuscrito para Revista Politécnica**. Cada afirmación categorizada cuenta con trazabilidad directa a los archivos de evidencia y las poblaciones experimentales verificadas.

Queda **terminantemente prohibido** incorporar en el artículo afirmaciones pertenecientes a la categoría `AFIRMACIONES_NO_RESPALDADAS` o presentar afirmaciones de `AFIRMACIONES_CON_LIMITACIONES` sin explicitar sus restricciones metodológicas.

---

## 2. Categoría 1: AFIRMACIONES_RESPALDADAS (Permitidas sin Reserva)

Afirmaciones respaldadas de forma concluyente por datos reproducibles, pruebas de hipótesis no paramétricas e intervalos de confianza estadísticos.

### Afirmación 1.1: La infraestructura DNS/TLS es la modalidad más costo-eficiente del sistema
- **Texto Aceptado:** *"La incorporación de características de infraestructura DNS y certificados TLS sobre el modelo puramente léxico ($M_0 \to M_1$) incrementa el F1-score en $+5.94$ puntos porcentuales (de $0.8658$ a $0.9252$, $p = 1.0 \times 10^{-5}$, McNemar exacto) y reduce la tasa de falsos positivos en un $81.3\%$ (del $3.20\%$ al $0.60\%$), sin requerir la descarga de contenido HTML."*
- **Evidencia y Archivo:** [`master_ablations_and_comparisons.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_ablations_and_comparisons.csv) (ABL-05A), [`master_inferential_statistics.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_inferential_statistics.csv) (TEST-05).
- **Población:** Partición independiente *host_unseen* ($N=691$).

### Afirmación 1.2: La Cascada Asimétrica no muestra inferioridad estadística frente al modelo monolítico $M_2$ (Análisis Exploratorio)
- **Texto Aceptado:** *"En un análisis exploratorio de no-inferioridad con un margen post-hoc de $\delta = 0.02$, la cascada adaptativa asimétrica (Política C) no muestra inferioridad estadística frente al clasificador monolítico multimodal $M_2$ ($\Delta F_1 = -0.0004$, $\text{IC}_{97.5\% \text{ unilateral}} = -0.0085 > -0.0200$, $p < 0.001$), logrando evitar el $67.87\%$ de las transferencias de contenido HTML. Al no mediar una preespecificación protocolizada antes de la inspección de datos, se declara formalmente como un análisis exploratorio y generador de hipótesis."*
- **Evidencia y Archivo:** [`master_inferential_statistics.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_inferential_statistics.csv) (TEST-02), [`fig_non_inferiority_forest_plot.png`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/figures/fig_non_inferiority_forest_plot.png).
- **Población:** Partición independiente *host_unseen* ($N=691$).

### Afirmación 1.3: Fuerte asociación diferencial entre clase y disponibilidad de modalidades (Patrón consistente con MNAR)
- **Texto Aceptado:** *"La disponibilidad de contenido web en sitios de phishing exhibe una asociación estadística altamente significativa con la clase del sitio (prueba exacta de Fisher $p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$), consistente con un patrón de pérdida no aleatoria debida a la corta vida media de los ataques y a bajas administrativas (*takedowns*). En un sondeo operativo en vivo ($N=600$), solo el $13.33\%$ de los sitios de phishing lograron adquisición completa, frente al $69.00\%$ de los sitios legítimos. Esto genera un sesgo de selección severo en análisis de casos completos y exige mecanismos de fallback, sin que esto constituya una prueba matemática formal del mecanismo no observado en el sentido estricto de Rubin."*
- **Evidencia y Archivo:** [`master_missing_modalities_fallback.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_missing_modalities_fallback.csv), [`fig_availability_by_class_and_source.png`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/figures/fig_availability_by_class_and_source.png).
- **Población:** Sondeo externo en vivo ($N=600$ ITE, $N=247$ Caso Completo).

### Afirmación 1.4: La imputación ingenua con ceros colapsa la especificidad operativa
- **Texto Aceptado:** *"Forzar la predicción del modelo multimodal $M_2$ imputando ceros estáticos cuando fallan las consultas de red dispara la tasa de falsos positivos del $3.38\%$ al $18.67\%$ (bloqueando erróneamente 56 de 300 sitios legítimos). En su lugar, la degradación progresiva a modelos léxicos ($M_0$) mantiene una tasa de falsos positivos controlada del $5.00\%$ y una precisión del $93.64\%$ sobre la totalidad de transacciones evaluadas."*
- **Evidencia y Archivo:** [`master_missing_modalities_fallback.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_missing_modalities_fallback.csv) (Estrategia F vs Estrategia C).
- **Población:** Sondeo externo en vivo ($N=600$).

### Afirmación 1.5: Cumplimiento de latencia para navegación interactiva (< 100 ms)
- **Texto Aceptado:** *"El endpoint de inspección síncrona de la API responde con una latencia mediana de $19.75 \text{ ms}$ ($P_{90} = 26.46 \text{ ms}$), satisfaciendo el umbral de percepción de fluidez de Nielsen (< 100 ms). La extensión Chrome actualiza su insignia de seguridad en $0.25 \text{ ms}$ en aciertos de caché local y en $20.00 \text{ ms}$ en consultas frías."*
- **Evidencia y Archivo:** [`master_systems_efficiency.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_systems_efficiency.csv), [`fig_latency_by_policy.png`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/figures/fig_latency_by_policy.png).
- **Población:** Benchmark de microservicios y cohorte auténtica ($N=83$).

---

## 2. Categoría 2: AFIRMACIONES_CON_LIMITACIONES (Permitidas con Declaración Explícita de Restricciones)

Afirmaciones empíricamente válidas pero que deben redactarse acompañadas de sus condiciones de contorno para no inducir a interpretaciones erróneas.

### Afirmación 2.1: La clasificación selectiva con abstención logra 100% de precisión
- **Condición Obligatoria:** Debe aclararse que este resultado aplica **únicamente a las muestras decididas** ($N=666$) y que deriva un $3.62\%$ de casos a triaje humano.
- **Texto Aceptado:** *"Al abstenerse en un $3.62\%$ de casos con entropía terminal superior a $0.50$ (derivados a analistas de seguridad), la clasificación selectiva ($M_5$) alcanza una precisión del $100.0\%$ (cero falsos positivos) con una cobertura del $96.38\%$. En pasarelas de alto tráfico masivo, este volumen de abstención requiere balancearse con la capacidad de respuesta del equipo forense."*
- **Evidencia y Archivo:** [`master_abstention_selective.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_abstention_selective.csv).

### Afirmación 2.2: Reducción de latencia en la cascada
- **Condición Obligatoria:** No debe confundirse la reducción de etapas lógicas ($50.9\%$) con la reducción temporal de pared.
- **Texto Aceptado:** *"La cascada original reduce el tiempo medio de respuesta en un $71.81\%$ respecto a la inspección visual completa $M_3$ y en un $31.44\%$ respecto a $M_2$ fijo sobre la cohorte verificada ($N=83$). Sin embargo, para el $24.2\%$ de muestras complejas que alcanzan la etapa final, la evaluación secuencial de modelos previos introduce un recargo computacional de $28.8 \text{ ms}$ en CPU."*
- **Evidencia y Archivo:** [`master_systems_efficiency.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_systems_efficiency.csv).

### Afirmación 2.3: Desempeño en validación externa
- **Condición Obligatoria:** Debe reportarse la discrepancia entre el feed de malware (URLhaus) y los feeds de phishing bancario/credenciales (PhishTank, OpenPhish).
- **Texto Aceptado:** *"En una cohorte externa de $1,200$ URLs con cero solapamiento de dominios, el modelo léxico $M_0$ alcanzó un F1 de $0.7118$ bajo el etiquetado histórico binario, penalizado por muestras de malware de URLhaus que carecían de formularios de suplantación. Al restringir la evaluación a sitios de phishing comprobado ($N=800$), el F1 se incrementa a $0.8268$ con una especificidad del $98.19\%$."*
- **Evidencia y Archivo:** [`master_external_generalization.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/06_publication_package/tables/master_external_generalization.csv).

---

## 3. Categoría 3: AFIRMACIONES_NO_RESPALDADAS (Terminantemente Prohibidas en el Artículo)

Afirmaciones que fueron refutadas por la auditoría, carecen de respaldo experimental o provienen de fórmulas sintéticas desacreditadas.

### ❌ Afirmación Prohibida 3.1: "El análisis visual $M_3$ incrementa sustancialmente la detección en todas las páginas"
- **Por qué está prohibida:** En la cohorte auténtica pareada de Chrome CDP ($N=83$), $M_3$ obtuvo un $F_1 = 0.8800$, inferior al $F_1 = 0.9020$ de $M_2$ y la cascada adaptativa, añadiendo más de $2.1$ segundos de latencia. Los resultados históricos favorables a $M_3$ se basaban en una constante sintética inventada ($+245 \text{ ms}$ en imágenes PIL) que fue eliminada por la auditoría.
- **Corrección Editorial:** Presentar $M_3$ no como clasificador universal de primera línea, sino como un módulo especializado de verificación dirigida de marcas (*targeted brand verifier*).

### ❌ Afirmación Prohibida 3.2: "La cascada ahorra exactamente el 75% del tiempo de navegación"
- **Por qué está prohibida:** La cascada evita el $75.83\%$ de las descargas de contenido HTML, pero la latencia de pared está dominada por las consultas de red $M_1$ ($1,272 \text{ ms}$). El ahorro real mediano de tiempo oscila entre el $31\%$ y el $71\%$ según el punto de comparación.
- **Corrección Editorial:** Usar la expresión exacta: *"evita el 75.8% del procesamiento de árbol DOM, traduciéndose en una reducción del 31.4% al 71.8% en la latencia de pared total"*.

### ❌ Afirmación Prohibida 3.3: "URLhaus es un feed representativo de phishing web"
- **Por qué está prohibida:** El análisis de contenido de la Fase 1 demostró que 96 de las muestras de URLhaus eran ejecutables binarios directos (`.exe`, `.apk`) alojados en servidores comprometidos, sin interfaz HTML ni suplantación de credenciales.
- **Corrección Editorial:** Declarar a URLhaus como fuente de distribución de malware y justificar metodológicamente el protocolo de filtrado de etiquetas.

### ❌ Afirmación Prohibida 3.5: "Se ha demostrado formalmente un mecanismo MNAR (Missing Not At Random)"
- **Por qué está prohibida:** Las pruebas estadísticas aplicadas (Fisher exact test $p = 4.28 \times 10^{-46}$, Odds Ratio $= 14.47$) demuestran una correlación empírica extrema entre la variable observada (clase) y la disponibilidad de modalidades. Sin embargo, demostrar formalmente el mecanismo teórico MNAR de Rubin requeriría probar dependencia estricta con valores no observados de las variables latentes.
- **Corrección Editorial:** Redactar como *"fuerte evidencia empírica de sesgo de disponibilidad diferencial asociado a la clase, consistente con un patrón de pérdida no aleatorio / sesgo de supervivencia"*.

### ❌ Afirmación Prohibida 3.6: "La prueba de no-inferioridad de la cascada es un ensayo confirmatorio preespecificado"
- **Por qué está prohibida:** El margen $\delta = 0.02$ y los umbrales de guarda asimétrica de la Política C fueron establecidos post-hoc tras inspeccionar los resultados y falsos negativos en la partición $N=691$. No existió protocolo de pre-registro pre-experimental.
- **Corrección Editorial:** Declarar expresamente el análisis como *"Análisis Exploratorio de No-Inferioridad (Hypothesis-Generating / Post-Hoc)"*.

### ❌ Afirmación Prohibida 3.7: "La Política C reduce los falsos negativos a 19"
- **Por qué está prohibida:** La verificación individual de las 691 predicciones pareadas en `cascade_paired_predictions.csv` y `early_exit_comparison.csv` arroja con exactitud: $\text{TP}=169, \text{TN}=497, \text{FP}=3, \text{FN}=22$ ($\text{Recall}=0.8848, \text{Precision}=0.9826$). El valor 19 fue una errata de transcripción manual previa.
- **Corrección Editorial:** Reportar con exactitud: *"la Política C reduce los falsos negativos de 25 a 22, rescatando 3 falsos negativos críticos respecto a la cascada simétrica original"*.

---
*Fin del documento de afirmaciones permitidas y prohibidas — Paquete de Transferencia.*
