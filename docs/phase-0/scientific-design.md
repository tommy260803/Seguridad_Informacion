# Diseno cientifico

## Pregunta de investigacion

¿Puede una politica de adquisicion adaptativa de evidencias multimodales mantener
o mejorar la deteccion y la robustez frente a pipelines fijos, reduciendo coste y
latencia y controlando falsos positivos mediante abstencion?

## Unidad de analisis y estimando

La unidad observada es `(url_canonical, observed_at)`. El estimando principal es
la diferencia de F1 y Recall de phishing entre configuraciones sobre la misma
particion de prueba. Para coste, el estimando es la diferencia media de tiempo de
CPU/sandbox, latencia y modalidades adquiridas por URL.

Las URLs del mismo dominio o campana no se tratan automaticamente como muestras
independientes. Los splits y el bootstrap deben agrupar por `registered_domain` o
`campaign_id` cuando esa agrupacion exista.

## Hipotesis y trazabilidad

| ID | Comparacion principal | Resultado primario | Evidencia de apoyo |
|---|---|---|---|
| H1 | M1/M2/M3 frente a M0 URL-only | Delta de F1 y Recall | IC del 95% y PR-AUC; FPR como guardrail |
| H2 | M4 adaptativo frente a M3 fijo | Modalidades y coste medio por URL | F1/Recall no inferiores dentro del margen definido en validation |
| H3 | M4/M5 frente a M0 en host-unseen y temporal | Degradacion relativa de F1/Recall | Diferencia de degradacion desde el split convencional |
| H4 | Datos limpios frente a perturbados | Caida de Recall y F1 | Exito de ataque, cambio de confianza y de ruta |
| H5 | M5 con abstencion frente a M4 | Riesgo selectivo a cobertura fijada | Curva coverage-risk, ECE y tasa de abstencion |
| H6 | Texto libre frente a plantilla grounded | Fidelidad y trazabilidad | Consistencia, completitud y estabilidad |

H2 usa un margen de no inferioridad elegido y documentado con validation antes de
abrir test. No se fija ahora porque debe guardar relacion con la variabilidad y el
baseline observados, y no con una cifra conveniente.

## Variables

### Independientes

- conjunto de modalidades: URL, infraestructura, contenido y visual;
- politica: fija o adaptativa;
- abstencion: desactivada o activada;
- escenario: convencional, host-unseen, temporal o adversarial;
- explicacion: libre o basada en evidencia estructurada.

### Dependientes

- deteccion: Precision, Recall, F1, Specificity, FPR, ROC-AUC y PR-AUC;
- calibracion: Brier score, ECE y reliability diagram;
- seleccion: coverage, selective risk y abstention rate;
- operacion: latencia, CPU, memoria, tiempo de sandbox, bytes, errores y timeouts;
- adaptacion: modalidades consultadas, punto de parada y ahorro frente a M3;
- explicacion: fidelidad, trazabilidad, completitud, consistencia y estabilidad.

### Controladas y posibles confusoras

- snapshot y fuente de datos;
- ventana temporal y disponibilidad del sitio al capturarlo;
- version de Public Suffix List, navegador, extractores y modelos;
- hardware, concurrencia, cache, region de red y limites del sandbox;
- balance/prevalencia del conjunto y agrupacion por dominio/campana;
- semillas, presupuesto de coste y orden de modalidades;
- antiguedad del dominio y disponibilidad parcial de WHOIS/RDAP/DNS.

## Definiciones operacionales

- `probability_phishing`: probabilidad posterior calibrada en validation para la
  etapa actual.
- `confidence`: probabilidad calibrada de la clase elegida. No se reporta como
  certeza epistemica.
- `uncertainty`: entropia binaria normalizada del score calibrado; se registrara
  tambien desacuerdo entre modelos si se incorpora un ensemble.
- `risk_score`: representacion 0-100 de `probability_phishing`, solo para interfaz;
  no es una variable independiente del modelo.
- `coverage`: fraccion de muestras para las que se emite clase binaria.
- `selective_risk`: tasa de error entre las muestras no abstencionadas.
- `cost`: vector medido, no una unica cifra: latencia, CPU, memoria, red, sandbox,
  llamadas externas, tokens y coste monetario estimado.

## Politica adaptativa inicial

Despues de cada etapa `s`, un modelo calibrado produce `p_s`. En validation se
seleccionan dos umbrales por etapa y un presupuesto:

- `p_s <= t_legitimate_s`: detener como legitimo;
- `p_s >= t_phishing_s`: detener como phishing;
- zona intermedia: adquirir la siguiente modalidad si queda presupuesto;
- sin siguiente modalidad o sin presupuesto: abstenerse.

La seleccion conjunta minimiza una funcion de perdida declarada que penaliza falso
negativo, falso positivo, abstencion y coste. Se publicaran analisis de sensibilidad
con mas de una razon de costes; la conclusion no dependera de una sola ponderacion.
La politica y sus umbrales se congelan antes de evaluar test.

## Matriz de ablacion

| ID | Modalidades | Politica | Abstencion |
|---|---|---|---|
| M0 | URL | Fija | No |
| M1 | URL + infraestructura | Fija | No |
| M2 | URL + infraestructura + contenido | Fija | No |
| M3 | Todas | Fija | No |
| M4 | Todas disponibles | Adaptativa | No, fuerza decision final |
| M5 | Todas disponibles | Adaptativa | Si |

La comparacion de coste principal es M4 contra M3. La comparacion de abstencion es
M5 contra M4 y debe hacerse a coberturas declaradas.

## Criterios de exito

No se fija un porcentaje absoluto antes del baseline. Una hipotesis queda apoyada
si el efecto va en la direccion preespecificada, su intervalo de confianza informa
una magnitud util y se cumplen los guardrails relevantes. Se reportaran resultados
nulos y adversos; no se cambiara la metrica primaria despues de abrir test.

El proyecto global se considera favorable si M4/M5 ofrecen una frontera de Pareto
mejor que los baselines en deteccion, coste y cobertura, muestran menor degradacion
en al menos uno de los escenarios no vistos sin empeorar materialmente los demas,
y producen explicaciones completamente trazables.
