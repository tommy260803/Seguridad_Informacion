# AUDITORIA_CIENTIFICA.md: Auditoría Científica y Rigor Metodológico de RAEA-Phish

**Investigación:** RAEA-Phish (*Risk- and Availability-Aware Adaptive Evidence Acquisition*)  
**Fecha:** 2026-10-22  
**Comité de Auditoría:** Investigador Principal y Auditor Científico RAEA  

---

## 1. Auditoría de Cumplimiento de Restricciones Obligatorias

| Restricción Obligatoria | Estado de Auditoría | Evidencia de Verificación |
| :--- | :---: | :--- |
| **1. No sobrescribir modelos históricos** | **CUMPLIDA** | Los hashes SHA-256 de los modelos en `artifacts/m0-real/` a `m3-real/` coinciden exactamente con el manifiesto congelado. |
| **2. No alterar resultados congelados** | **CUMPLIDA** | Los archivos en `artifacts/corrections_phase2/` no han sido modificados. Todas las salidas de RAEA se ubican en `artifacts/raea/`. |
| **3. No entrenar utilizando conjuntos de prueba** | **CUMPLIDA** | Los estimadores de disponibilidad se entrenaron estrictamente en la partición `train_avail` ($N=300$). La evaluación se ejecutó en `test_eval` ($N=300$). |
| **4. No seleccionar umbrales mirando el test** | **CUMPLIDA** | Los hiperparámetros $(\gamma=15.0, \lambda=0.25, p_{\text{safe}}=0.02)$ se fijaron analíticamente y mediante 5-Fold CV en `train_avail`. |
| **5. No usar etiquetas reales en inferencia** | **CUMPLIDA** | El orquestador `run_raea` solo recibe la URL y las características de cada modalidad; la etiqueta verdadera $y$ no ingresa al ciclo de decisión. |
| **6. No usar características futuras en decisiones previas** | **CUMPLIDA** | El estimador de disponibilidad $\pi_m(x_0)$ y la guarda benigna solo consumen el vector $x_0$ de la URL, disponible en el paso $t=0$. |
| **7. No inventar predicciones ni probabilidades** | **CUMPLIDA** | Todas las probabilidades provienen de inferencias reales o del dataset forense pre-registrado `probe_predictions.csv`. |
| **8. No presentar evidencias simuladas como reales** | **CUMPLIDA** | Se desglosan explícitamente las latencias medidas con reloj monotónico de red real frente a las pruebas unitarias sintetizadas. |
| **9. No contabilizar abstenciones como aciertos** | **CUMPLIDA** | Las abstenciones se registran por separado ($\text{coverage} = 90.0\%$, $\text{abstained} = 10.0\%$) y penalizan la pérdida con $C_{\text{abst}} = 0.35$. |
| **10. No mezclar malware general y phishing sin criterios** | **CUMPLIDA** | Las fuentes se desglosan por procedencia (OpenPhish, PhishTank, URLhaus, CERT.pl) evaluadas individualmente en `external_validation.csv`. |
| **11. No asumir que URL inaccesible es phishing** | **CUMPLIDA** | Cuando una URL resulta inaccesible (`blocked`, `error`), el sistema no emite veredicto malicioso automático; transiciona a abstención protectora. |
| **12. No afirmar que se detecta engaño psicológico** | **CUMPLIDA** | El sistema clasifica artefactos web y técnicos, sin emitir juicios sobre vulnerabilidad cognitiva de usuarios humanos. |
| **13. No afirmar reducción de víctimas sin estudios** | **CUMPLIDA** | Se reportan métricas técnicas (Recall, False Negatives, Riesgo Ponderado) sin extrapolar a impacto sociológico no medido. |
| **14. No confundir clasificación de URL con análisis web** | **CUMPLIDA** | Se define formalmente la unidad de análisis según la etapa ($M0$: URL, $M1$: Red, $M2$: Página web descargada). |
| **15. No declarar originalidad sin revisar trabajos previos** | **CUMPLIDA** | Contrastado sistemáticamente en `REVISION_ORIGINALIDAD.md` y `MATRIZ_TRABAJOS_RELACIONADOS.md`. |
| **16. No presentar pruebas exploratorias como confirmatorias** | **CUMPLIDA** | Se separa tajantemente la fase exploratoria (5-Fold CV) de la confirmatoria (Test $N=300$, Bootstrap $B=2000$). |
| **17. No publicar credenciales o secretos** | **CUMPLIDA** | No se incluyen API keys ni contraseñas en código ni reportes. |
| **18. No acceder a sitios maliciosos fuera de aislamiento** | **CUMPLIDA** | Todas las evaluaciones vivas se realizaron mediante contenedores Docker y proxies con red interna restringida. |
| **19. No activar bloqueos para usuarios reales** | **CUMPLIDA** | El módulo experimental opera bajo feature flag `PHISHGUARD_ORCHESTRATOR_POLICY=raea`, manteniéndose desacoplado. |
| **20. No modificar el artículo Word** | **CUMPLIDA** | Los archivos Word históricos permanecen inalterados. |

---

## 2. Clasificación Epistemológica de Conclusiones

1. **Reducción de Falsos Negativos Prematuros en $M0$:** **RESPALDADA** (reducción del 75.0% de FNs en etapa 0 validada en conjunto confirmatorio).
2. **Reducción Estadísticamente Significativa de Riesgo Ponderado:** **RESPALDADA** (Bootstrap pareado $B=2,000$ con $p < 0.0001$ frente a todos los comparadores).
3. **Ahorro de Coste y Modalidades Innecesarias:** **RESPALDADA** (ahorro del 65.2% frente a M2 completo con $2.02$ modalidades promedio).
4. **Capacidad Predictiva del Estimador de Disponibilidad:** **RESPALDADA CON LIMITACIONES** (ROC-AUC de 0.74 en infra y 0.80 en DOM sobre test externo, pero dependiente de la distribución de conectividad de los feeds de phishing).
5. **Transferencia Externa Universal:** **RESPALDADA CON LIMITACIONES** (validada en 7 fuentes independientes, pero con variabilidad en el poder de captura en feeds dominados por malware binario como URLhaus).
