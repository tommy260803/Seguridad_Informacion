# Fase 8 - Abstención y calibración

La evaluación selectiva calcula una confianza basada en la distancia de la
probabilidad a 0.5. Los casos por debajo del umbral se abstienen y producen
`uncertain`; los restantes se miden con cobertura, tasa de abstención y riesgo
selectivo. `select_abstention_threshold` debe ejecutarse únicamente sobre
validation y luego congelarse para test.

La curva `coverage_risk_curve` exporta puntos reproducibles para comparar
calibración y calidad bajo distintos niveles de cobertura. No se fija un
porcentaje de éxito a priori: el umbral se elige según el protocolo experimental.
