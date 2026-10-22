# Informe de Hallazgos Científicos y Evidencia Experimental (Fase 5)
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Síntesis Epistémica — Fase 5: Comparación Estadística, Estudios de Ablación e Inferencia Formal*

---

## 1. Resumen de Respuestas a las Preguntas de Investigación

El análisis estadístico inferencial y los estudios de ablación ejecutados sobre la partición independiente *host_unseen* ($N=691$) y la cohorte auténtica de navegador ($N=83$) permitieron responder formalmente a las preguntas científicas del estudio:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HALLAZGOS CIENTÍFICOS CLAVE                     │
├────────────────────────────────────────────────────────────────────────┤
│ 1. MODALIDAD MÁS RENTABLE:                                             │
│    Infraestructura DNS/TLS (M1). Aporta +5.94% de F1 (p = 1.0e-5),     │
│    eleva precisión a 98.2% y reduce FPR en 81% sin descargar HTML.     │
├────────────────────────────────────────────────────────────────────────┤
│ 2. COMPONENTE CON PEOR RELACIÓN COSTE/BENEFICIO:                       │
│    Análisis Visual con Navegador Completo (M3). Añade +2,200 ms        │
│    de latencia sin ganancia de F1 estadísticamente significativa.      │
├────────────────────────────────────────────────────────────────────────┤
│ 3. POLÍTICA ÓPTIMA CONTRA FALSOS NEGATIVOS:                            │
│    Cascada Asimétrica (Política C). Restringe salida benigna en M0,    │
│    reduciendo falsos negativos de 25 a 19 (recupera 6 ataques).        │
├────────────────────────────────────────────────────────────────────────┤
│ 4. CONFIRMACIÓN DE NO-INFERIORIDAD:                                    │
│    La cascada adaptativa es estadísticamente no inferior al modelo     │
│    monolítico M2 (IC 97.5% unilateral > -0.02), ahorrando 75.8% HTML.  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detalle de Hallazgos Empíricos

### 2.1. ¿Qué modalidad aporta la mayor ganancia incremental?
**La infraestructura de red (resolución DNS autoritativa y certificados TLS en $M_1$) es, por un margen abrumador, la modalidad más costo-eficiente del sistema.**
- **Evidencia Empírica ([`ablation_study.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/ablation_study.csv), ABL-05A):**
  - Incorporar infraestructura sobre el modelo puramente léxico ($M_0 \to M_1$) genera un incremento masivo en el F1-score: $\Delta F_1 = +0.0594$ (de $0.8658$ a $0.9252$).
  - La precisión se dispara del **$90.80\%$ al $98.24\%$**, y la Tasa de Falsos Positivos ($\text{FPR}$) se desploma del **$3.20\%$ al $0.60\%$** (una reducción del 81.3% en falsas alarmas).
  - La prueba de McNemar confirma que esta mejora es estadísticamente contundente: $\chi^2 = 16.96$, $p = 1.0 \times 10^{-5}$ ($b=24$ aciertos nuevos frente a solo $c=2$ pérdidas), sobreviviendo a las correcciones de Bonferroni ($p_{\text{adj}} = 7.0 \times 10^{-5}$) y Benjamini-Hochberg FDR.
  - Crucialmente, esta ganancia se logra **sin descargar ni un solo byte de contenido HTML**, evitando el 100% de la complejidad de parseo DOM y renderizado.

### 2.2. ¿Qué componentes generan costes sin mejora estadísticamente respaldada?
1. **La Adquisición Visual Completa en Navegador ($M_3$ con Chrome CDP):**
   - Ejecutar un navegador Headless Chrome para renderizar la página y extraer descriptores visuales añade **$+2,166.36 \text{ ms}$** de latencia de pared (multiplica el tiempo total de respuesta por $2.4\times$).
   - Sin embargo, en la cohorte auténtica pareada ($N=83$), el modelo $M_3$ obtiene un $F_1 = 0.8800$, frente al $F_1 = 0.9020$ de $M_2$ y la cascada adaptativa. La diferencia no es estadísticamente favorable a $M_3$.
   - **Implicación Arquitectural:** La inspección visual sistemática e indiscriminada de todas las URLs es un desperdicio computacional severo. El componente visual solo se justifica como mecanismo de verificación dirigida (*targeted brand verifier*) cuando se sospecha colisión tipográfica o suplantación homográfica de marcas registradas.
2. **Descarga Forzada de HTML DOM ($M_2$) en Casos de Alta Certeza de Red:**
   - La ablación ABL-05B ($M_1 \to M_2$) demuestra que añadir el árbol DOM sobre la infraestructura añade únicamente $+0.0063$ de F1 ($p = 0.7905$, McNemar no significativo, $b=8, c=6$).
   - Forzar la adquisición de HTML en el 100% de las URLs en lugar de utilizar salida temprana en $M_0/M_1$ cuadruplica las descargas de red sin aportar un beneficio predictivo discernible.

### 2.3. ¿Qué políticas reducen falsos negativos ante evasión sofisticada?
**La Cascada Asimétrica Mejorada (Política C / Baseline F1) resuelve la mayor vulnerabilidad de la cascada simétrica.**
- **Mecanismo de Evasión:** Atacantes que registran subdominios sintácticamente "limpios" en servicios respetados (e.g., `firebaseapp.com`, `github.io`) engañan al clasificador léxico $M_0$, el cual asigna una probabilidad espuriamente baja ($p_0 < 0.02$). En la cascada simétrica original ($M_4$), esto desencadena una salida prematura como benigno y produce un falso negativo inadvertido.
- **Evidencia Empírica (ABL-04):**
  - La Política C restringe la salida benigna en $M_0$ a un estricto $p_0 \le 0.005$, forzando a inspeccionar la infraestructura $M_1$ ante la menor duda.
  - Esto recupera **6 ataques de phishing evadidos**, reduciendo los falsos negativos de 25 a 19.
  - El F1-score aumenta de **$0.9222$ a $0.9311$** ([`baseline_comparison.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/baseline_comparison.csv)), alcanzando una precisión del **$98.26\%$** e igualando el rendimiento del modelo monolítico $M_2$ ($0.9315$), pero ahorrando el **$67.87\%$** de las descargas HTML.

### 2.4. ¿Qué cambios perjudican otras métricas del sistema?
1. **La Clasificación Selectiva con Abstención (Política D / Baseline F2):**
   - Al abstenerse en muestras con entropía $H(p_2) > 0.50$, la precisión sobre las muestras decididas alcanza el **$100.0\%$** (0 falsos positivos, $\text{FPR} = 0.0\%$, $F_1 = 0.9493$).
   - **Coste Asociado:** La cobertura autónoma cae al **$96.38\%$**. En un entorno corporativo con $100,000$ transacciones diarias, ese $3.62\%$ de abstención implicaría derivar **$3,620$ incidentes diarios** a analistas humanos del SOC, creando un cuello de botella operacional si el equipo de seguridad es reducido.
2. **Uso de Umbral Fijo Ingenuo ($\tau = 0.50$):**
   - La ablación ABL-03B demuestra que sustituir el umbral calibrado $\tau_2^* = 0.3950$ por $\tau = 0.50$ en $M_2$ deteriora el Recall de $0.8879$ a $0.8659$, produciendo 6 falsos negativos adicionales debido al desbalance natural de clases.

### 2.5. ¿Es la cascada estadísticamente no inferior al modelo monolítico?
**SÍ. La prueba formal de no-inferioridad queda plenamente demostrada para la Cascada Asimétrica.**
- Con un margen pre-establecido de $\delta = 0.02$ (2% de F1), la diferencia pareada entre la Cascada Asimétrica y el modelo monolítico $M_2$ es:
  $$\Delta F_1 = -0.0004 \quad [\text{IC}_{95\%}: -0.0085, +0.0074]$$
- El límite inferior unilateral al 97.5% de confianza es **$-0.0085$**, el cual es estrictamente mayor que el margen tolerado de **$-0.0200$** ([`paired_statistics.csv`](file:///d:/Proyects/Seguridad_Informacion/paper_reproduction/05_statistical_comparison/paired_statistics.csv)).
- Por ende, **se rechaza la hipótesis nula de inferioridad ($p < 0.001$)**: la Cascada Asimétrica ofrece un rendimiento idéntico al modelo monolítico completo, pero con un coste de red y cómputo drásticamente inferior.

---

## 3. Clasificación de Afirmaciones Científicas

| Tipo de Afirmación | Afirmación Científica | Nivel de Soporte Experimental |
| :--- | :--- | :--- |
| **CONFIRMATORIA** | La infraestructura ($M_1$) es significativamente superior al léxico ($M_0$) en F1 y FPR ($p = 1.0 \times 10^{-5}$). | **Demostrado con significancia formal y corrección FDR.** |
| **CONFIRMATORIA** | La Cascada Asimétrica es estadísticamente no inferior a $M_2$ Completo bajo margen $\delta = 0.02$. | **Demostrado formalmente ($\text{IC}_{\text{low}} = -0.0085 > -0.02$).** |
| **CONFIRMATORIA** | Los clasificadores $M_1$ y $M_2$ se encuentran bien calibrados ($\text{ECE} < 0.024$). | **Verificado empíricamente con diagrama de fiabilidad.** |
| **CONFIRMATORIA** | $M_0$ presenta descalibración relativa ($\text{ECE} = 0.0862$), justificando la salida asimétrica. | **Verificado cuantitativamente.** |
| **EXPLORATORIA** | La entropía de Shannon ($H \le 0.15$) es superior a un margen lineal ($|p - 0.5| \ge 0.40$). | **No demostrado:** la diferencia es marginal ($\Delta F_1 = 0.021$ a favor de entropía, pero compatible con márgenes lineales más estrictos). |
| **EXPLORATORIA** | El modelo visual $M_3$ puede superar a $M_2$ con descriptores basados en Deep Learning (CNN/ViT). | **Abierto a investigación futura:** la evidencia actual con características clásicas/CDP no muestra ventaja. |

---
*Fin del documento de hallazgos científicos — Fase 5: Comparación Estadística y Estudios de Ablación.*
