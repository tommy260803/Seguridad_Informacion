# Informe de Limitaciones Científicas y Metodológicas: Rendimiento y Benchmarking de Sistemas
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Transparencia Científica — Fase 4: Rendimiento Computacional, Latencia y Costes de Sistemas*

---

## 1. Propósito y Alcance del Documento

La evaluación experimental de la eficiencia computacional en sistemas de ciberseguridad requiere un análisis riguroso de las condiciones de contorno y las hipótesis simplificadoras bajo las cuales se obtuvieron los resultados. 

Este documento expone detalladamente las limitaciones metodológicas, amenazas a la validez externa y compromisos técnicos identificados en el benchmark de rendimiento de **PhishPe**, en estricto cumplimiento de los estándares editoriales de *Revista Politécnica*.

---

## 2. Inventario de Amenazas a la Validez y Limitaciones Específicas

### 2.1. La Falacia de Equivalencia entre Etapas Lógicas y Ahorro Temporal
- **Manifestación:** En la evaluación histórica de la cascada se reportó con frecuencia una reducción del 50.9% en el número medio de modalidades requeridas (pasando de 4.0 modalidades teóricas a 1.96 modalidades lógicas por URL).
- **Amenaza Científica:** **Ahorrar el 50% de las etapas lógicas no equivale a ahorrar el 50% del tiempo de respuesta del usuario.**
- **Explicación Física:** Los costes temporales de las modalidades son radicalmente asimétricos y no lineales:
  - Etapa 0 ($M_0$ Léxico): $\approx 14.7 \text{ ms}$ (Cómputo en CPU).
  - Etapa 1 ($M_1$ Red/Infraestructura): $\approx 1,272.7 \text{ ms}$ (Mediana I/O de sockets en Internet).
  - Etapa 2 ($M_2$ HTML DOM): $\approx 8.9 \text{ ms}$ adicionales de parseo DOM (asumiendo que el cuerpo HTTP ya fue transferido en $M_1$).
  - Etapa 3 ($M_3$ Chrome CDP Visual): $\approx 2,166.4 \text{ ms}$ adicionales de inicialización y renderizado de navegador.
- **Consecuencia:** Salir en $M_0$ ahorra más del **$99.5\%$** del tiempo total de pared al evitar completamente las conexiones de red. Por el contrario, detenerse en $M_1$ en lugar de $M_2$ solo ahorra **$8.9 \text{ ms}$** de parseo DOM (un ahorro temporal marginal de menos del **$1.0\%$** de la latencia acumulada).
- **Directriz para el Manuscrito:** Queda prohibido en el texto del artículo utilizar indistintamente "reducción de etapas" y "reducción de tiempo". El manuscrito debe distinguir explícitamente entre *reducción de adquisiciones de contenido* (75.8%) y *reducción real de latencia mediana de pared* (54.3% a 71.8%).

### 2.2. Restricción Muestral de la Cohorte Visual Auténtica ($N=83$)
- **Contexto:** En auditorías previas se descubrió que los experimentos históricos utilizaban una fórmula sintética simplificada ($245.0 \text{ ms} + \text{latencia PIL}$) para simular la adquisición visual de $M_3$.
- **Corrección Auditada:** Dicha fórmula sintética fue eliminada en su totalidad, restringiendo la evaluación de $M_3$ a mediciones 100% auténticas obtenidas mediante el protocolo Headless Chrome DevTools Protocol (CDP) sobre 83 URLs del conjunto de prueba independiente *host_unseen*.
- **Limitación Inherente:** Si bien esta decisión metodológica garantiza integridad científica total (cero latencias inventadas), el tamaño muestral de $N=83$ reduce la potencia estadística para percentiles extremos ($P_{99}$). Aunque los intervalos de confianza al 95% calculados por bootstrap confirman la significancia estadística de la ventaja de la cascada ($p = 1.66 \times 10^{-13}$), se recomienda en trabajos futuros ampliar la captura auténtica de navegador a gran escala.

### 2.3. Variabilidad de Red Pública vs. Determinismo Algorítmico Local
- **Condición de Prueba:** Para garantizar la reproducibilidad estricta del benchmark algorítmico local (Nivel A), las características y árboles DOM se evaluaron a partir de muestras archivadas y archivos HTML reales en disco. La telemetría de red (Nivel B) se derivó de trazas de adquisición directa registradas en el repositorio.
- **Amenaza Externa:** En un despliegue operativo en tiempo real sobre Internet, las latencias de red fluctúan sustancialmente en función de:
  - Congestión de rutas BGP y distancia geográfica a los servidores de nombres autoritativos.
  - Mecanismos de limitación de tasa (*rate limiting*) o desafíos CAPTCHA / Cloudflare impuestas por los sitios visitados.
  - Fluctuaciones del ancho de banda y latencia de última milla del usuario final.
- **Mitigación:** La separación estricta de Niveles (Nivel A, Nivel B, Nivel C) documentada en el protocolo garantiza que cualquier fluctuación de red externa no sea atribuida espuriamente como ineficiencia del clasificador de aprendizaje automático.

### 2.4. Diferencias entre Invocación Monohilo y Concurrencia Asíncrona
- **Escenario Medido:** El benchmark de inferencia de modelos se ejecutó de forma secuencial monohilo para aislar el coste intrínseco de cada predicción por muestra sin contención de recursos.
- **Realidad de Producción:** En un servidor de pasarela empresarial o un entorno multiusuario, FastAPI gestiona peticiones de forma asíncrona mediante un bucle de eventos (`asyncio`) y trabajadores dedicados (`celery` / `worker.py`). Bajo alta concurrencia:
  - El uso de CPU puede saturarse si múltiples inferencias de LightGBM / scikit-learn compiten por los mismos hilos de ejecución.
  - La contención en la resolución DNS puede mitigarse mediante resolución asíncrona concurrente con `aiodns` o cachés locales como `dnsmasq`.

### 2.5. Especificaciones del Hardware de Banco vs. Dispositivos Móviles / IoT
- **Entorno del Experimento:** Las mediciones se realizaron en una estación de trabajo con procesador Intel Core i5-13600K de 14 núcleos físicos con alta frecuencia de reloj (hasta 5.1 GHz en núcleos P).
- **Limitación de Extrapolación:** En dispositivos clientes con procesadores de bajo consumo (e.g., teléfonos móviles, terminales punto de venta o microcomputadores Raspberry Pi en redes perimetrales), el tiempo de cómputo en CPU para parseo de DOM ($M_2$) o extracción léxica ($M_0$) podría incrementarse en un factor de $3\times$ a $5\times$, haciendo que la salida temprana en $M_0$ sea aún más crítica para la experiencia de usuario.

---

## 3. Resumen de Buenas Prácticas Metodológicas Derivadas

| Práctica Rechazada | Práctica Obligatoria en el Manuscrito | Justificación Científica |
| :--- | :--- | :--- |
| **Sumar etapas lógicas como si fuesen tiempos lineales** | Reportar latencia de pared total distinguiendo red de cómputo CPU. | La red de Internet es 100 veces más costosa que el procesamiento local. |
| **Utilizar fórmulas sintéticas para $M_3$ (+245 ms)** | Utilizar mediciones auténticas de Chrome CDP o reportar explícitamente proyecciones. | Evita inventar o subestimar el coste real de renderizado en navegador. |
| **Ocultar el sobrecoste de la cascada en casos complejos** | Reportar la sobrecarga de evaluación secuencial ($28.8 \text{ ms}$ en CPU). | Transparencia total sobre los compromisos del pipeline adaptativo. |
| **Medir solo con caché caliente** | Reportar por separado el rendimiento con caché fría y con caché caliente. | Proporciona una cota superior e inferior realista para el usuario final. |

---
*Fin del documento de limitaciones — Fase 4: Rendimiento y Benchmarking de Sistemas.*
