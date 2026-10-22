# POLITICA_RAEA.md: Especificación Operativa de la Política RAEA-Phish

**Método:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Componente Central:** Motor de Decisión Secuencial

---

## 1. Parámetros Operativos de la Política

| Parámetro | Símbolo | Valor por Defecto | Rango Válido | Propósito |
| :--- | :---: | :---: | :---: | :--- |
| **Razón de Costes Asimétricos** | $\gamma = C_{FN} / C_{FP}$ | 15.0 | $[5.0, 50.0]$ | Penalización relativa de dejar pasar un sitio de phishing frente a una falsa alarma. |
| **Factor de Coste de Adquisición** | $\lambda$ | 0.25 | $[0.05, 1.0]$ | Ponderación de la latencia y coste de adquisición en la función de selección. |
| **Pérdida por Abstención** | $C_{\text{abst}}$ | 0.35 | $[0.1, 0.9]$ | Penalización por emitir un veredicto de incertidumbre preventiva. |
| **Umbral de Guarda Benigna en $M0$** | $p_{\text{safe}}$ | 0.02 | $[0.005, 0.05]$ | Máxima probabilidad permitida para salida benigna prematura en $M0$. |
| **Umbral de Disponibilidad Mínima** | $\tau_{\text{avail\_min}}$ | 0.10 | $[0.05, 0.30]$ | Cota inferior de disponibilidad esperada para autorizar un intento de adquisición. |
| **Presupuesto Total de Coste** | $B$ | 3.0 | $[0.5, 5.0]$ | Límite máximo acumulado de coste por URL. |

---

## 2. Flujo de Decisión Paso a Paso

### Paso 0: Inferencia Léxica Inicial ($M0$)
1. Extraer características $x_0$ de la URL canonicalizada.
2. Comprobar presencia en el filtro Bloom de Tranco Top-1M:
   - Si está en Tranco y no presenta subdominio sospechoso ni homógrafos, creencia $p_0 \approx 0.0001$. Cumple la guarda benigna $\to$ **Terminar como Benigno ($a_{\text{benign}}$)** en $< 0.1\text{ ms}$.
3. Infección con modelo $M0$: obtener probabilidad calibrada $p_0$.
4. Evaluar Guarda Benigna:
   $$\text{GuardaBenignaValida} = (p_0 \le p_{\text{safe}}) \land (\text{RiesgoLéxico}(x_0) = \text{False})$$
   donde $\text{RiesgoLéxico}(x_0)$ evalúa:
   - Host es dirección IP numérica (`is_ip_host == True`).
   - Servicio de acortamiento de URLs (`is_shortener == True`).
   - Presencia de caracteres IDN/Punycode (`is_idn_punycode == True`).
   - Múltiples subdominios no institucionales ($n_{\text{labels}} \ge 4$).
5. Si $\text{GuardaBenignaValida}$ es falsa, la opción $a_{\text{benign}}$ se deshabilita para $t=0$.
6. Calcular $\mathcal{Q}(a)$ para todas las acciones $a \in \{a_{\text{phish}}, a_{\text{benign}}, a_{\text{abstain}}, a_{\text{infra}}\}$.
7. Seleccionar $a^* = \arg\min_a \mathcal{Q}(a)$.
   - Si $a^* \in \{a_{\text{phish}}, a_{\text{benign}}, a_{\text{abstain}}\}$, finalizar.
   - Si $a^* = a_{\text{infra}}$, avanzar al Paso 1.

### Paso 1: Inferencia de Infraestructura de Red ($M1$)
1. Consultar DNS y handshake TLS.
2. Si la consulta tiene éxito ($\mathbf{s}_1 = \text{success}$):
   - Extraer $x_1$ y evaluar $p_1 = M_1([x_0, x_1])$.
3. Si la consulta falla ($\mathbf{s}_1 \in \{\text{blocked}, \text{error}, \text{timeout}\}$):
   - Ajustar creencia con factor de fallo: $p_1 = p_0 + \delta_{\text{fail}}(m_1)$.
4. Evaluar costes $\mathcal{Q}(a)$ para $a \in \{a_{\text{phish}}, a_{\text{benign}}, a_{\text{abstain}}, a_{\text{content}}\}$.
5. Si $a^* = a_{\text{content}}$ y $B_1 \ge \text{Coste}(m_2)$ y $\pi_{\text{content}}(x_0) \ge \tau_{\text{avail\_min}}$, avanzar al Paso 2.
6. En caso contrario, emitir la mejor acción terminal disponible.

### Paso 2: Inferencia de Contenido DOM ($M2$)
1. Descargar HTML y parsear estructura DOM.
2. Si la descarga tiene éxito:
   - Extraer $x_2$ y evaluar $p_2 = M_2([x_0, x_1, x_2])$.
3. Si falla:
   - Ajustar creencia y registrar incidencia forense.
4. Evaluar $\mathcal{Q}(a)$ para $a \in \{a_{\text{phish}}, a_{\text{benign}}, a_{\text{abstain}}, a_{\text{visual}}\}$.
5. Si $a^* = a_{\text{visual}}$ y presupuesto suficiente, avanzar al Paso 3; si no, emitir acción terminal.

### Paso 3: Inspección Visual y Sandbox CDP ($M3$)
1. Renderizar página en sandbox aislado Playwright.
2. Extraer $x_3$ y evaluar $p_3 = M_3([x_0, x_1, x_2, x_3])$.
3. Emitir veredicto final:
   - Phishing si $\mathcal{Q}(a_{\text{phish}}) \le \min(\mathcal{Q}(a_{\text{benign}}), \mathcal{Q}(a_{\text{abstain}}))$.
   - Benigno si $\mathcal{Q}(a_{\text{benign}}) \le \min(\mathcal{Q}(a_{\text{phish}}), \mathcal{Q}(a_{\text{abstain}}))$.
   - Abstención en caso de conflicto irreducible de evidencia.
