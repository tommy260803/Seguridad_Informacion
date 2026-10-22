# DIAGRAMA_ARQUITECTURA.md: Arquitectura e Integración de RAEA-Phish

**Método:** RAEA-Phish  
**Subsistema:** Orquestador de Inferencia Adaptativa en PhishPe  

---

## 1. Diagrama de Arquitectura Modular de RAEA-Phish

```mermaid
flowchart TD
    subgraph Entrada_Sistema ["Capa de Ingesta y Preprocesamiento"]
        InURL["URL Candidata"] --> Canonicalizer["Canonicalizador PSL (PublicSuffixList)"]
        Canonicalizer --> FeatExtract0["Extractor Léxico Autoridad (x0, 11-16 vars)"]
        Canonicalizer --> TrancoCheck{"Tranco Top-1M Bloom Filter"}
    end

    TrancoCheck -- "Presente y Seguro" --> EarlyWhitelist["Veredicto Rápido: Legítimo (< 0.1 ms)"]
    TrancoCheck -- "No presente o Sospechoso" --> IngestRAEA["Ingreso al Motor RAEA"]

    subgraph Modulo_RAEA ["Módulo Experimental RAEA-Phish (phishguard_orchestrator.raea)"]
        IngestRAEA --> StateInit["Inicializar DecisionState (S0)"]
        
        StateInit --> EstAvail["AvailabilityEstimator: P(avail_m | x0)"]
        StateInit --> EstCost["AcquisitionCostEstimator: E[C(m) | x0]"]
        StateInit --> EstRisk["RiskEstimator: R(a_term | p_t)"]
        
        EstRisk --> GuardCheck{"¿t=0 y a=benign?"}
        GuardCheck -- "Sí" --> BenignGuard{"Evaluar Guarda Benigna (p_safe + RiesgoLéxico)"}
        BenignGuard -- "Viola Guarda" --> DisallowBenign["Q(benign) = Infinito (Forzar Adquisición)"]
        BenignGuard -- "Pasa Guarda" --> AllowBenign["Q(benign) = gamma * p0"]
        GuardCheck -- "No" --> AllowBenign
        
        AllowBenign --> ActionSelector["ActionSelector: argmin_a Q(a | S_t)"]
        DisallowBenign --> ActionSelector
        EstAvail --> ActionSelector
        EstCost --> ActionSelector
        
        ActionSelector --> DecDecision{"Tipo de Acción Seleccionada"}
    end

    DecDecision -- "a_phish" --> ResPhish["Veredicto: Phishing"]
    DecDecision -- "a_benign" --> ResBenign["Veredicto: Legítimo"]
    DecDecision -- "a_abstain" --> ResAbstain["Veredicto: Abstención / Advertencia"]
    
    DecDecision -- "a_acquire_m" --> Adapter["EvidenceAcquisitionAdapter"]
    
    subgraph Adquisicion_Modalidades ["Subsistemas de Adquisición de Evidencia"]
        Adapter --> DNS_TLS["M1: DNS / TLS (phishguard_infra)"]
        Adapter --> HTTP_DOM["M2: HTTP / DOM (phishguard_content)"]
        Adapter --> CDP_Visual["M3: Playwright Sandbox CDP (phishguard_visual)"]
    end

    DNS_TLS --> UpdateState["Actualizar Estado S_t+1 (Datos o Fallback de Inaccesibilidad)"]
    HTTP_DOM --> UpdateState
    CDP_Visual --> UpdateState
    
    UpdateState --> LoopBack["Siguiente Ciclo de Decisión"]
    LoopBack --> ActionSelector
```

---

## 2. Puntos de Acoplamiento y Convivencia Arquitectónica

```mermaid
flowchart LR
    API_Client["Cliente API / Navegador Web"] --> RouterFastAPI["FastAPI Server (/analyses, /check)"]
    
    RouterFastAPI --> Dispatcher{"Selector de Política"}
    
    Dispatcher -- "Por Defecto (policy='entropy_cascade')" --> LegacyEngine["Orquestador Clásico (engine.py, Shannon Entropy)"]
    Dispatcher -- "Experimental (policy='raea')" --> RAEAEngine["Orquestador RAEA-Phish (raea.engine)"]
    
    LegacyEngine --> SharedModels["Modelos Congelados M0-M3"]
    RAEAEngine --> SharedModels
    
    LegacyEngine --> SharedExtractors["Extractores DNS, DOM, Visual"]
    RAEAEngine --> SharedExtractors
```

---

## 3. Garantías de No Regresión y Aislamiento

1. **Aislamiento Funcional:** La lógica de RAEA-Phish reside en su propio espacio de nombres (`phishguard_orchestrator.raea`), sin modificar clases base de `engine.py`.
2. **Activación Segura:** Si la variable de entorno `PHISHGUARD_ORCHESTRATOR_POLICY` no está definida, el sistema ejecuta de manera 100% idéntica la cascada de entropía histórica.
3. **Auditabilidad Completa:** Cada ciclo de inferencia de RAEA produce una traza estructurada con los valores $\mathcal{Q}(a)$, la disponibilidad estimada $\pi_m$, el riesgo de Bayes y el estado de adquisición.
