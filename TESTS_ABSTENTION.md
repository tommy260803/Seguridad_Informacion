# REGISTRO DE PRUEBAS DE CONSISTENCIA DE ABSTENCIÓN
**Fecha:** 22 de Octubre de 2026  
**Fase:** 2 (Reconciliación de Abstenciones y Métricas)  

---

## 1. COMPROBACIÓN ARITMÉTICA DE POBLACIONES

Para la partición de prueba confirmatoria `test_eval` ($N=300$):

| Magnitud | Fórmula | Valor Observado | Estado de Verificación |
|---|---|:---:|:---:|
| Población Total ($N$) | $N_{\text{dec}} + N_{\text{abst}}$ | $240 + 60 = 300$ | **VERIFICADO** |
| Matriz Selectiva | $TP_{\text{sel}} + FP_{\text{sel}} + TN_{\text{sel}} + FN_{\text{sel}}$ | $125 + 20 + 90 + 5 = 240$ | **VERIFICADO** |
| Cobertura ($\phi$) | $N_{\text{dec}} / N$ | $240 / 300 = 0.8000$ (80.0%) | **VERIFICADO** |
| Tasa de Abstención | $N_{\text{abst}} / N$ | $60 / 300 = 0.2000$ (20.0%) | **VERIFICADO** |
| Desglose de Abstención | $\text{Abst}_{\text{legit}} + \text{Abst}_{\text{phish}}$ | $40 + 20 = 60$ | **VERIFICADO** |

---

## 2. RECONCILIACIÓN DE POLÍTICAS FORZADAS

| Política | Suma de Matriz | $TP$ | $FP$ | $TN$ | $FN$ | F1-Score | Recall |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Selectiva (Decididos, $N=240$)** | 240 | 125 | 20 | 90 | 5 | **0.9091** | **0.9615** |
| **Forced Fail-Open ($N=300$)** | 300 | 125 | 20 | 130 | 25 | 0.8475 | 0.8333 |
| **Forced Fail-Closed ($N=300$)** | 300 | 145 | 60 | 90 | 5 | 0.8169 | 0.9667 |
| **Forced Threshold 0.5 ($N=300$)** | 300 | 127 | 22 | 128 | 23 | 0.8495 | 0.8467 |

### Conclusión de Auditoría
El enigma de la matriz de confusión idéntica a M1 queda formalmente resuelto:
1. La coincidencia matemática ocurrió porque el script original forzó las abstenciones a 0 (*Fail-Open*), colapsando las 40 abstenciones legítimas en $TN$ ($90+40=130$) y las 20 abstenciones de phishing en $FN$ ($5+20=25$).
2. Cuando se evalúa la capacidad de RAEA en la población donde decide ($N=240$), el modelo exhibe un desempeño superior con $F1 = 0.9091$ y un recall de $96.15\%$, reduciendo los falsos negativos de 25 a únicamente 5.
