# REVISION_ORIGINALIDAD.md: Revisión de Originalidad Científica y Estado del Arte

**Método Propuesto:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Sistema Base:** PhishPe / PhishGuard Pro  
**Área Temática:** Seguridad de la Información, Aprendizaje Automático Sensible al Costo y Clasificación Multimodal Secuencial.

---

## 1. Contexto Científico y Marco Teórico

La detección de sitios web de phishing se ha abordado tradicionalmente desde tres paradigmas:
1. **Modelos Unimodales Léxicos (URL-only):** Alta velocidad computacional pero susceptibles a falsos positivos en marcas emergentes y falsos negativos ante ofuscación o servicios de redirección/acortamiento.
2. **Modelos Multimodales Exhaustivos (Monolíticos):** Extraen simultáneamente URL, DNS, certificados TLS, contenido DOM y renderizado visual mediante navegadores automatizados. Aunque logran altos valores de F1 en conjuntos estáticos, su coste en latencia (1.5 a 4 segundos por URL) y ancho de banda resulta prohibitivo para navegación interactiva en tiempo real.
3. **Cascadas Adaptativas Basadas en Incertidumbre:** Introducidas recientemente (p. ej., arquitecturas de *early-exit* en redes neuronales o cascadas de clasificadores basadas en entropía de Shannon). Si la entropía $H(p)$ es baja, el sistema interrumpe la adquisición de evidencia adicional.

---

## 2. Revisión de Campos Conexos

### 2.1. Adquisición Activa de Características (*Active Feature Acquisition - AFA*)
- **Antecedentes:** Trabajos clásicos de Ji & Carin (2007), Saar-Tsechansky et al. (2009), y formulaciones modernas de MDP (Markov Decision Processes) como EDDI (Ma et al., ICML 2019) y Shim et al. (AAAI 2018).
- **Limitación en Ciberseguridad:** Los métodos AFA tradicionales asumen que cualquier característica solicitada puede obtenerse de forma determinista pagando un coste fijo $c_m$. En la detección web real, esta suposición es **falsa**: los servidores de phishing sufren caídas, bloqueos por cortafuegos o eliminación de registros DNS, lo que induce una **tasa de indisponibilidad observada superior al 40%**.

### 2.2. Clasificación Presupuestada (*Budgeted Classification*)
- **Antecedentes:** Trapeznikov & Saligrama (AISTATS 2013), Wang et al. (ICML 2014) sobre árboles y cascadas con restricciones presupuestarias globales $\sum c_m \le B$.
- **Limitación:** El presupuesto suele modelarse como un valor escalar abstracto, sin desacoplar el coste computacional directo de la probabilidad de éxito de la adquisición en tiempo real.

### 2.3. Aprendizaje Sensible al Coste (*Cost-Sensitive Learning*)
- **Antecedentes:** Elkan (IJCAI 2001), He & Garcia (IEEE TKDE 2009). La matriz de costes penaliza asimétricamente el error de clasificación: típicamente el coste de un falso negativo ($C_{FN}$, permitir que un usuario acceda a un sitio de phishing y sufra robo de credenciales) es de 10 a 50 veces mayor que el coste de un falso positivo ($C_{FP}$, generar una advertencia innecesaria o requerir confirmación).
- **Limitación:** Los enfoques tradicionales aplican el coste únicamente al umbral de clasificación final sobre un vector de características completo y preexistente, no como conductor de la política secuencial de adquisición.

### 2.4. Clasificación Selectiva y Abstención (*Selective Classification*)
- **Antecedentes:** Chow (1970), Geifman & El-Yaniv (NeurIPS 2017 - SelectiveNet). Permite al clasificador abstenerse cuando la confianza no garantiza el nivel de riesgo deseado.
- **Limitación:** En las cascadas de phishing existentes (como la etapa M5 de PhishPe), la abstención se evalúa solo al agotar todas las modalidades, sin ponderar si una abstención preventiva temprana es más económica que una consulta a modalidades complejas que probablemente fallarán.

### 2.5. Aprendizaje con Modalidades Faltantes (*Missing-Modality Learning*)
- **Antecedentes:** Imputación de características, redes generativas multimodales o enmascaramiento durante el entrenamiento.
- **Diferencia:** RAEA-Phish no busca imputar la modalidad faltante con datos sintéticos (lo cual violaría la restricción de rigor forense), sino modelar explícitamente la distribución a priori del éxito de adquisición $P(\text{available} \mid x_{0})$ para decidir si vale la pena pagar el coste de intento.

---

## 3. Delimitación de Originalidad de RAEA-Phish

### Lo que ya existía en el sistema base PhishPe:
- Modelos entrenados congelados $M0$ (léxico), $M1$ (infraestructura), $M2$ (contenido HTML) y $M3$ (visión CDP).
- Cascada lineal basada puramente en umbral simétrico de Entropía de Shannon ($H(p) \le 0.15 \implies \text{parada}$).
- Criterio de abstención estático al final de la cascada ($H(p) > 0.20$ o $0.50$).
- Extracción de características por etapas y almacenamiento forense.

### La Contribución Original Específica de RAEA-Phish:
1. **Formulación de Adquisición Secuencial Sensible al Riesgo y Disponibilidad:** Una política analítica que evalúa para cada estado observado $S_t = (x_{0:t}, \mathcal{M}_{consultadas}, B_{restante})$ el valor esperado del riesgo de Bayes combinado con el coste de consulta ponderado por la disponibilidad estimada:
   $$\mathcal{Q}(a \mid S_t) = \mathbb{E}[\text{Riesgo}(y, \hat{y}) \mid S_t, a] + \lambda \cdot \mathbb{E}[\text{Coste}(a) \mid S_t]$$
2. **Estimador de Disponibilidad $P(\text{avail}_m \mid x_0)$:** Un modelo calibrado que predice la viabilidad de obtener DNS/TLS o DOM basándose únicamente en características léxicas y de reputación de la URL (p. ej., IPs directas, dominios recién registrados, TLDs de alto abuso, acortadores), evitando desperdiciar tiempo de espera y timeouts en endpoints inaccesibles.
3. **Guarda Asimétrica contra Salidas Benignas Prematuras (*Anti-Premature Benign Termination*):** Restricción derivada formalmente de la matriz de costes $C_{FN} \gg C_{FP}$, que prohíbe terminar en la etapa $M0$ declarando "legítimo" si existen señales residuales de riesgo léxico, mitigando los falsos negativos de alta confianza inducidos por atajos de aprendizaje (*shortcut learning*).
4. **Mecanismo Integrado de Decisión, Adquisición o Abstención:** Una arquitectura desacoplada y auditable que permite a los sistemas de inspección web (gateways y extensiones de navegador) operar bajo compromisos adaptativos rigurosos.
