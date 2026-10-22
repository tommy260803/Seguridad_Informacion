# Síntesis de Hallazgos Científicos y Principios Epistémicos
**Proyecto PhishPe / PhishGuard Pro — Publicación Revista Politécnica (Ecuador)**  
*Documento de Principios de Ingeniería y Ciberseguridad para el Autor/Redactor*

---

## 1. Los Cuatro Principios Científicos de PhishPe

A partir de las auditorías experimentales, se derivaron cuatro principios fundamentales que deben estructurar la discusión científica y las conclusiones del artículo:

### Principio 1: La Asimetría de Valor de las Modalidades Sensoriales
*No todas las modalidades aportan valor proporcional a su coste computacional.*
- En la literatura previa se asumía que agregar modalidades sucesivamente (Léxico $\to$ Red $\to$ HTML $\to$ Visual) producía incrementos acumulativos similares de detección.
- **La evidencia de PhishPe refuta esta hipótesis:**
  - El salto de Léxico ($M_0$) a Infraestructura ($M_1$) produce el **$90.4\%$ de la ganancia total del sistema** ($\Delta F_1 = +0.0594$, colapsando falsas alarmas del 3.2% al 0.6%), con una inversión de red mínima (DNS y cabeceras TLS).
  - El salto de Infraestructura a DOM HTML ($M_2$) aporta solo un modesto $+0.6\%$ de F1 (no significativo, $p=0.791$), a cambio de descargar y parsear el cuerpo completo del documento.
  - La inspección visual indiscriminada ($M_3$) genera una penalización masiva de latencia ($+2.16 \text{ s}$) sin ganancia de F1 en la cohorte auténtica.
- **Recomendación de Diseño:** La infraestructura debe ser la columna vertebral de cualquier sistema perimetral de phishing; el DOM debe ser un filtro secundario y el análisis visual debe reservarse como verificador dirigido.

### Principio 2: La No-Linealidad del Ahorro Temporal en Sistemas de Red
*Ahorrar el 50% de las etapas lógicas no equivale a ahorrar el 50% del tiempo de respuesta del usuario.*
- Las etapas de inferencia local en CPU operan en el rango de los **$14 \text{ ms}$**. Las etapas de red e I/O operan en el rango de los **$1,200 \text{ ms}$ a $3,800 \text{ ms}$**.
- Por ende:
  - Salir temprano en $M_0$ produce un ahorro temporal colosal ($>99.5\%$), pues evita tocar los sockets de red.
  - Detenerse en $M_1$ frente a $M_2$ ahorra únicamente el parseo DOM local ($8.9 \text{ ms}$), lo que representa menos del $1.0\%$ de la latencia acumulada.
- **Directriz de Publicación:** Las métricas de ahorro deben desagregarse con rigor: ahorro de peticiones de red/HTML (75.8%) frente a reducción real de latencia mediana de pared (31.4% a 71.8%).

### Principio 3: La Necesidad de Guardias Asimétricas ante Evasión Léxica
*El phishing moderno en la nube explota la descalibración de los modelos léxicos.*
- Los ataques alojados en servicios de infraestructura compartida reputados (Google Firebase, GitHub Pages, Amazon S3) exhiben nombres de dominio legítimos y estructuras sintácticas breves que inducen una probabilidad espuriamente baja en modelos basados en URL ($p_0 < 0.02$).
- En una cascada simétrica estándar ($H \le 0.15$), esta baja probabilidad desencadena una salida prematura como benigno, produciendo falsos negativos inadvertidos (13 de los 25 FN de la cascada simétrica).
- **Solución PhishPe:** La Cascada Asimétrica impone un umbral de salida benigna ultra-conservador ($p_0 \le 0.005$). Si la probabilidad es levemente dudosa, se prohíbe la salida temprana y se obliga a verificar la infraestructura $M_1$, recuperando 6 de estos ataques y elevando el F1 a 0.9311.

### Principio 4: La Falacia del Caso Completo y el Fenómeno MNAR
*En ciberseguridad web, la ausencia de datos no es aleatoria y evaluar sólo supervivientes distorsiona la realidad.*
- Los sitios de phishing tienen una vida media activa extremadamente corta (< 24 horas). Al realizar un sondeo operativo en vivo, el $86.7\%$ de los sitios de phishing ya son inalcanzables por caídas de servidor o bloqueos de registradores (`dns_empty`, `connection_error`).
- Evaluar exclusivamente las URLs que completan todas las modalidades sensoriales ($N=247$) incurre en un sesgo de supervivencia catastrófico, alterando la prevalencia real de phishing del 50% al 16% e ignorando al 86.7% de los ataques reales.
- El principio de Intención de Evaluar (ITE) y las políticas de degradación progresiva (*fallback* a $M_0$) son obligatorias para garantizar que el sistema proteja al usuario incluso ante servidores degradados o desconectados.

---
*Fin del documento de hallazgos científicos — Paquete de Transferencia.*
