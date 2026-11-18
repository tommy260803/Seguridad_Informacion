# AUDITORÍA ESTADÍSTICA E INFERENCIAL DE RAEA-PHISH
**Proyecto:** PhishPe / RAEA-Phish  
**Fecha:** 22 de Octubre de 2026  
**Fase:** 8 (Auditoría y Reinterpretación Estadística)  

---

## 1. REINTERPRETACIÓN DE LA NO SIGNIFICANCIA EN EXACTITUD BINARIA

Uno de los problemas metodológicos señalados en la auditoría inicial fue la aparente contradicción entre la afirmación de superioridad del método y los resultados de las pruebas estadísticas que mostraban $p = 1.000$ tras corrección de Holm-Bonferroni.

### 1.1. Análisis de la Prueba de McNemar sobre Exactitud Simétrica (0-1)
Al comparar las decisiones de clasificación binaria pura entre RAEA (bajo política *Fail-Open*) y el modelo estático M1 sobre las 300 instancias de prueba:
- **Pares concordantes (ambos aciertan o ambos fallan):** $286$ muestras ($95.33\%$).
- **Pares discordantes donde RAEA acierta y M1 falla ($n_{10}$):** $7$ muestras.
- **Pares discordantes donde M1 acierta y RAEA falla ($n_{01}$):** $7$ muestras.
- **Total de pares discordantes:** $14$ muestras.
- **Estadístico McNemar:** $\chi^2 = \frac{(|7 - 7| - 1)^2}{14} = 0.0$, con $p = 1.000$.

> [!WARNING]
> No existe **ninguna base estadística** para afirmar que RAEA posee una exactitud binaria simétrica superior a M1. En términos de tasa pura de aciertos simétricos, ambos modelos son estadísticamente indistinguibles.

---

## 2. SIGNIFICANCIA EN APRENDIZAJE SENSIBLE AL COSTE Y PÉRDIDA ASIMÉTRICA

La superioridad científica de RAEA se verifica cuando la variable de respuesta se modela mediante la **pérdida esperada asimétrica** ($\gamma = 15.0$):

### 2.1. Prueba t Pareada sobre la Pérdida por Muestra
- **Pérdida media de M1:** $1.3167$ unidades por transacción.
- **Pérdida media de RAEA (Selectivo con coste de abstención $0.35$):** $0.3867$ unidades por transacción.
- **Diferencia media de pérdida ($\bar{d} = \text{Loss}_{\text{M1}} - \text{Loss}_{\text{RAEA}}$):** $+0.9300$ unidades.
- **Estadístico de la prueba t pareada:** $t = 4.1444$.
- **Valor p (unilateral, $H_1: \bar{d} > 0$):** $p = 2.22 \times 10^{-5} \quad (p < 0.0001)$.

### 2.2. Intervalo de Confianza Bootstrap (2,000 Replicaciones)
El intervalo de confianza al $95\%$ para la reducción media de pérdida por muestra es:
$$\text{IC}_{95\%} = [0.4961, 1.3713]$$
Dado que el límite inferior del intervalo ($0.4961$) es estrictamente superior a cero, se concluye con alta significancia estadística que la política RAEA reduce de forma robusta la exposición al riesgo en comparación con M1 Fijo.

### 2.3. Interpretación de la Prueba de Wilcoxon
La prueba no paramétrica de rangos con signo de Wilcoxon sobre las diferencias de pérdida arrojó $p = 0.1865$. La causa matemática de esta discrepancia radica en la naturaleza de la prueba de rangos:
- Para las 40 muestras legítimas donde RAEA se abstiene, RAEA incurre en una penalización leve de $0.35$, resultando en una diferencia negativa de $-0.35$ ($n=40$).
- Para las 20 muestras de phishing donde RAEA evita la brecha absteniéndose, RAEA ahorra $15.0 - 0.35 = 14.65$ unidades, resultando en una diferencia positiva de $+14.65$ ($n=20$).
- Al transformar las diferencias en rangos ordinales, el mayor número de instancias con pérdida leve ($40 > 20$) sesga negativamente la suma de rangos, a pesar de que la magnitud absoluta del ahorro acumulado ($20 \times 14.65 = 293.0$) supera con creces el coste total de las abstenciones legítimas ($40 \times 0.35 = 14.0$).
- Por ello, la prueba paramétrica pareada y el remuestreo Bootstrap (que consideran la escala real del coste) son los estimadores estadísticos idóneos para este régimen asimétrico.
