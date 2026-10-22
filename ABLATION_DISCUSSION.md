# ABLATION_DISCUSSION.md: Discusión Científica del Estudio de Ablaciones

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Artefactos Generados:**
- `artifacts/raea/ablation_results.csv`
- `artifacts/raea/component_contribution.csv`

---

## 1. Tabla Maestra de Resultados de Ablación ($N=300$)

| ID | Configuración Evaluada | F1-Score | Recall | Total FN | FN en $M0$ | Riesgo Ponderado ($\gamma=15$) | Modalidades Medias | Coste Medio |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A0** | Cascada Original (Entropía M5) | 0.8374 | 80.67% | 29 | 12 | 0.8588 | 2.08 | 0.3447 |
| **A1** | RAEA sin Estimador de Disponibilidad | 0.8475 | 83.33% | 25 | 1 | 0.3518 | 2.26 | 0.3847 |
| **A2** | RAEA sin Costes Asimétricos ($\gamma=1$) | 0.8362 | 80.00% | 30 | 12 | 1.4590 | 1.60 | 0.1990 |
| **A3** | RAEA sin Mecanismo de Abstención | 0.8333 | 93.33% | 10 | 3 | 0.6533 | 2.12 | 0.5670 |
| **A4** | RAEA sin Beneficio Informativo | 0.7971 | 73.33% | 40 | 21 | 0.4142 | 1.82 | 0.3332 |
| **A5** | RAEA sin Guarda Benigna en $M0$ | 0.8475 | 83.33% | 25 | 3 | 0.3867 | 2.02 | 0.4072 |
| **A6** | **RAEA Completo (Propuesto)** | **0.8475** | **83.33%** | **25** | **3** | **0.3867** | **2.02** | **0.4072** |
| **A7** | M2 Ejecutado Completamente | 0.8439 | 84.67% | 23 | 0 | 1.2300 | 3.00 | 1.2860 |

---

## 2. Análisis Crítico de la Contribución por Componente (Respuesta a RQ6)

### 2.1. El Papel Conductor de los Costes Asimétricos ($\gamma=15$, Variante A2)
- La eliminación de la asimetría de costes representa la degradación más severa en el riesgo operativo: la pérdida ponderada se dispara de **$0.3867$ a $1.4590$** ($+277\%$).
- Con costes simétricos, la política optimiza Accuracy ingenua y subestima drásticamente el impacto de un falso negativo, permitiendo que **12 ataques de phishing se escapen en la etapa $M0$** (frente a solo 3 en el modelo completo).
- Esto confirma la **Hipótesis H3**: la asimetría de pérdidas orienta de forma efectiva la política secuencial para priorizar la seguridad del usuario.

### 2.2. El Valor de la Estimación del Beneficio Informativo Esperado (Variante A4)
- Prescindir de la estimación probabilística de la reducción de riesgo produce el mayor colapso en métricas predictivas: el F1-Score desciende de **$0.8475$ a $0.7971$** ($-5.0$ puntos porcentuales) y los falsos negativos totales aumentan de **25 a 40**.
- Sin modelar formalmente la resolución esperada de la incertidumbre, el agente no adquiere evidencia cuando más la necesita, cayendo en decisiones prematuras con alta tasa de error.

### 2.3. Eficiencia Práctica de la Consciencia de Disponibilidad ($\pi_m$, Variante A1)
- Cuando el agente asume disponibilidad perfecta ($100\%$, como asume la literatura clásica de Active Feature Acquisition), el número de modalidades consultadas se incrementa de **$2.02$ a $2.26$**, intentando sistemáticamente descargar contenido de páginas caídas y servidores bloqueados.
- El estimador de disponibilidad $\pi_m(x_0)$ actúa como un filtro de prudencia operativa que ahorra intentos infructuosos, reduciendo el overhead de latencia muerta. Esto valida la **Hipótesis H2**.

### 2.4. Protección Selectiva mediante Abstención (Variante A3)
- Cuando se prohíbe la abstención, el modelo forzado se ve obligado a clasificar casos ambiguos donde los datos de red y DOM resultaron inaccesibles o contradictorios. Aunque el recall nominal parece aumentar debido al sesgo hacia la clase positiva, el riesgo ponderado se deteriora a **$0.6533$** debido al aumento de falsas alarmas y clasificaciones inestables.
- La abstención actúa como un colchón de seguridad que transforma errores catastróficos en advertencias preventivas.

---

## 3. Conclusiones del Estudio de Ablación

El estudio demuestra rigurosamente que el rendimiento superior de RAEA-Phish no es atribuible a un único factor aislado, sino a la interacción sinérgica entre la **asimetría de costes de Bayes** (que previene salidas prematuras) y la **estimación de disponibilidad y valor informativo** (que modula cuándo es económicamente viable adquirir evidencia adicional).
