# AUDITORÍA DE LATENCIAS OPERACIONALES Y MODELO DE COSTES
**Proyecto:** PhishPe / RAEA-Phish  
**Fecha:** 22 de Octubre de 2026  
**Fase:** 5 (Auditoría de Latencias y Costes Observados)  

---

## 1. MEDICIONES DE LATENCIA EN TIEMPO REAL

Todas las latencias utilizadas para la evaluación operacional provienen de las mediciones empíricas cronometradas durante la ejecución de los sondeos de Cohorte 2 (`probe_predictions.csv`):

| Componente Modal | Media (ms) | Desviación Estándar (ms) | Mediana P50 (ms) | Percentil P95 (ms) | Máximo (ms) |
|---|:---:|:---:|:---:|:---:|:---:|
| **$M_0$ Léxico (URL)** | $0.065$ | $0.036$ | $0.058$ | $0.099$ | $0.782$ |
| **$M_1$ Red (DNS + TLS)** | $1258.37$ | $1150.73$ | $958.61$ | $3571.73$ | $6585.44$ |
| **$M_2$ Contenido (HTTP + DOM)** | $1408.10$ | $2259.37$ | $860.18$ | $4820.50$ | $43602.53$ |

### 1.1. Perfil de Latencia por Política en `test_eval` ($N=300$)
- **$M_0$ Fijo:** Mediana $0.058$ ms, P95 $0.099$ ms (cómputo puramente local en CPU).
- **$M_1$ Fijo:** Mediana $1012.94$ ms, P95 $3629.73$ ms.
- **$M_2$ Fijo (Completo):** Mediana $1971.16$ ms, P95 $7402.03$ ms.
- **RAEA-Phish:** Mediana $886.47$ ms, P95 $4885.05$ ms.

> [!TIP]
> RAEA-Phish logra una latencia mediana $126.47$ ms menor que $M_1$ Fijo ($886.47$ ms frente a $1012.94$ ms) debido a que para las URLs con indicios deterministas inmediatos ($p_0 \le 0.02$ o $p_0 \ge 0.98$) se detiene de inmediato en $M_0$ ($0.058$ ms).

---

## 2. RECONCILIACIÓN ENTRE COSTE NORMALIZADO Y TIEMPO REAL

Para evitar confusiones en publicaciones científicas, se debe diferenciar con claridad el **coste normalizado de decisión** de los costes económicos o latencias físicas:

1. **Unidades de Coste Normalizado:**
   - Adquisición de Red: $C_{\text{base}} = 0.20$ si tiene éxito, $0.80$ si falla o se bloquea (penalización por reintentos/espera).
   - Adquisición de Contenido: $C_{\text{base}} = 0.50$ si tiene éxito, $1.20$ si expira o falla.
   - Presupuesto Total Máximo: $B_0 = 3.00$ unidades.
2. **Interpretación:**
   El coste normalizado no equivale a dólares ni a segundos directamente, sino a una función de utilidad adimensional que pondera la penalización computacional y de ancho de banda respecto al riesgo de seguridad.
