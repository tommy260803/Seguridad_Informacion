# PSEUDOCODIGO.md: Algoritmos Formales de RAEA-Phish

**Método:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Formato:** Algoritmo estructurado en notación matemática y de ingeniería

---

## Algoritmo 1: Ciclo Principal de Decisión Secuencial RAEA

```text
Entrada:
    url: Cadena de URL a inspeccionar
    M0, M1, M2, M3: Modelos preentrenados congelados
    G_avail: Estimador de disponibilidad de modalidades
    params: Parámetros (gamma, lambda, C_abst, p_safe, tau_avail_min, Budget)

Salida:
    decision: { "phishing", "legitimate", "uncertain" }
    p_final: Probabilidad de phishing final
    modalities_used: Lista de modalidades consultadas
    log_trace: Registro detallado de transiciones y valores Q

1:  x0, flags_lexicos = ExtraerCaracteristicasURL(url)
2:  if EstaEnTrancoTop1M(url) y not flags_lexicos.sospechoso:
3:      retornar ("legitimate", 0.0001, ["url"], [LogTranco()])
4:
5:  p_actual = Calibrar(M0.predict_proba(x0))
6:  modalidades_usadas = ["url"]
7:  presupuesto_restante = params.Budget
8:  t = 0
9:  historial_estados = {}
10: log_trace = []
11:
12: mientras True hacer:
13:     // Evaluar acciones terminales
14:     Q_phish = 1.0 * (1.0 - p_actual)
15:     
16:     // Guarda Asimétrica Benigna en M0
17:     si t == 0 y (p_actual > params.p_safe o flags_lexicos.tiene_riesgo_evasion):
18:         Q_benign = INFINITO   // Prohibido salir como benigno prematuramente
19:     si no:
20:         Q_benign = params.gamma * p_actual
21:     
22:     Q_abstain = params.C_abst
23:     
24:     // Evaluar acciones de adquisición disponibles
25:     Q_acq = {}
26:     siguiente_modalidad = ObtenerSiguienteModalidad(modalidades_usadas)
27:     
28:     si siguiente_modalidad != NULO:
29:         pi_disp = G_avail.predecir_disponibilidad(siguiente_modalidad, x0)
30:         coste_esp = EstimarCosteEsperado(siguiente_modalidad, pi_disp)
31:         
32:         si coste_esp <= presupuesto_restante y pi_disp >= params.tau_avail_min:
33:             // Calcular reducción esperada de riesgo
34:             riesgo_actual = min(Q_phish, Q_benign, Q_abstain)
35:             riesgo_post_esp = EstimarRiesgoPosteriorEsperado(siguiente_modalidad, p_actual, pi_disp, x0)
36:             Q_acq[siguiente_modalidad] = riesgo_post_esp + params.lambda * coste_esp
37:         fin si
38:     fin si
39:     
40:     // Selección de acción óptima
41:     acciones_candidatas = {
42:         "phish": Q_phish,
43:         "benign": Q_benign,
44:         "abstain": Q_abstain
45:     }
46:     para cada (mod, q_val) en Q_acq hacer:
47:         acciones_candidatas["acquire_" + mod] = q_val
48:     fin para
49:     
50:     a_optima = argmin_{a} acciones_candidatas[a]
51:     log_trace.append(RegistrarPaso(t, p_actual, acciones_candidatas, a_optima))
52:     
53:     si a_optima == "phish":
54:         retornar ("phishing", p_actual, modalidades_usadas, log_trace)
55:     si a_optima == "benign":
56:         retornar ("legitimate", p_actual, modalidades_usadas, log_trace)
57:     si a_optima == "abstain":
58:         retornar ("uncertain", p_actual, modalidades_usadas, log_trace)
59:     
60:     // Ejecutar Adquisición
61:     mod = ExtraerNombreModalidad(a_optima)
62:     estado_acq, datos_mod, latencia_ms = AdquirirModalidad(mod, url)
63:     presupuesto_restante = presupuesto_restante - ConvertirLatenciaACoste(latencia_ms)
64:     historial_estados[mod] = estado_acq
65:     modalidades_usadas.append(mod)
66:     
67:     si estado_acq == "success":
68:         p_actual = PredecirConModeloEtapa(mod, x0, datos_mod)
69:     si no:
70:         p_actual = AjustarPorFalloAdquisicion(p_actual, mod, estado_acq)
71:     fin si
72:     
73:     t = t + 1
74: fin mientras
```

---

## Algoritmo 2: Guarda Asimétrica Benigna en $M0$

```text
Entrada:
    p0: Probabilidad predicha por M0
    x0_features: Vector de características léxicas
    p_safe: Umbral máximo seguro (nominal 0.02)

Salida:
    es_seguro: Booleano indicando si se autoriza terminar como legítimo en t=0

1:  si p0 > p_safe:
2:      retornar Falso
3:  si x0_features["is_ip_host"] == 1:
4:      retornar Falso   // Un host por IP nunca debe aceptarse como benigno sin red
5:  si x0_features["is_shortener"] == 1:
6:      retornar Falso   // Una URL acortada oculta el destino real
7:  si x0_features["is_idn_punycode"] == 1:
8:      retornar Falso   // Presencia de homógrafos sospechosos
9:  si x0_features["host_label_count"] >= 4 y not x0_features["in_tranco_top1m"]:
10:     retornar Falso   // Exceso de subdominios fuera de listas de reputación
11: retornar Verdadero
```
