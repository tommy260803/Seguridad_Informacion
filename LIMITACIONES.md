# LIMITACIONES.md: Limitaciones Teóricas, Empíricas y Operativas

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Directriz:** Declaración honesta, rigurosa y transparente de limitaciones científicas y técnicas para la redacción de artículos en revistas de alto impacto.

---

## 1. Limitaciones del Modelado Teórico

1. **Horizonte Miope de Decisión (One-Step Lookahead):**
   - La función $\mathcal{Q}(a \mid S_t)$ evalúa la ganancia esperada de la siguiente modalidad inmediata en la jerarquía ($M0 \to M1 \to M2 \to M3$). No resuelve un árbol POMDP completo con horizonte infinito mediante programación dinámica hacia atrás, debido a que en inspección web la latencia admisible para decidir es de sub-milisegundo.
2. **Dependencia Lineal de Secuencia de Modalidades:**
   - La política actual respeta la dependencia técnica natural (no es posible extraer el DOM de una página sin antes resolver el DNS de la infraestructura). En consecuencia, no evalúa consultar contenido antes que DNS, lo cual restringe el espacio de exploración a secuencias acotadas.
3. **Calibración de la Pérdida por Abstención ($C_{\text{abst}}$):**
   - El parámetro $C_{\text{abst}} = 0.35$ se seleccionó empíricamente para reflejar el coste de generar una pantalla de advertencia preventiva. En entornos empresariales donde la tolerancia a la interrupción de usuarios es extraordinariamente baja, $C_{\text{abst}}$ debería calibrarse con métricas operativas del SOC.

---

## 2. Limitaciones de los Datos y de la Evaluación Empírica

1. **Tamaño Muestral del Sondeo Multimodal en Vivo ($N=600$ y $N=300$ Test):**
   - Mientras que la evaluación a nivel URL cuenta con miles de muestras, el sondeo en vivo con extracción completa de DNS, certificados TLS, descarga HTTP y parseo DOM se acotó a 600 URLs para respetar límites de cuota de feeds públicos y estabilidad de red. Aunque las pruebas de significancia demuestran $p < 0.0001$, estudios futuros se beneficiarán de cohortes de decenas de miles de sondeos simultáneos.
2. **Volatilidad Temporal Extrema en Phishing:**
   - La vida media de los sitios de phishing es de pocas horas. Sitios clasificados como "inaccesibles" durante el sondeo podrían haber estado en línea minutos antes. El sistema maneja esto mediante la categoría `uncertain` / abstención, pero el desfase temporal entre la denuncia del feed y el escaneo sigue siendo un reto perenne.
3. **Ausencia de Pruebas con Usuarios Finales en Entornos Reales:**
   - Conforme a las restricciones obligatorias de seguridad y ética (Reglas 12, 13 y 19), no se realizaron pruebas de navegación en vivo sobre personal no técnico para medir la tasa de interacción con las pantallas de advertencia.

---

## 3. Limitaciones Operativas y de Despliegue

1. **Dependencia de la Infraestructura de Sandbox Docker:**
   - La extracción de la modalidad visual ($M3$) requiere un daemon de Docker y contenedores Playwright operativos. En despliegues donde Docker no esté disponible (p. ej., clientes livianos o proxies sin virtualización), la cascada se trunca automáticamente en $M2$.
2. **Cloaking Avanzado y Contramedidas de Evasión Dinámica:**
   - Si un atacante despliega mecanismos antibot que sirven páginas en blanco o HTTP 403 a las IPs de los crawlers pero muestran el portal de phishing a usuarios residenciales, el extractor DOM no captura los campos de login. RAEA-Phish mitiga esto mediante la detección de fallos y la emisión de abstenciones preventivas, pero la evasión antibot sofisticada requiere proxies residenciales rotativos.
