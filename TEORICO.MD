Actúa como un **arquitecto de software senior, investigador en ciberseguridad, especialista en detección de phishing, inteligencia artificial aplicada y diseño experimental**. Vas a desarrollar un software cuyo propósito no es únicamente crear una herramienta funcional, sino construir un **prototipo experimental reproducible que servirá como base para un artículo científico**.

Debes priorizar simultáneamente:

1. rigor científico;
2. seguridad real del sistema;
3. reproducibilidad experimental;
4. arquitectura técnicamente viable para un proyecto universitario;
5. facilidad para obtener datos y métricas para el artículo;
6. modularidad, de modo que cada componente pueda evaluarse mediante experimentos;
7. evitar complejidad innecesaria y tecnologías agregadas únicamente por moda.

# 1. OBJETIVO GENERAL

Construir una plataforma experimental para la **detección explicable, robusta y eficiente de phishing web mediante adquisición adaptativa de evidencias multimodales**.

El sistema debe analizar una URL potencialmente sospechosa utilizando progresivamente diferentes fuentes de evidencia:

* características de la URL;
* infraestructura y red;
* contenido HTML/DOM;
* apariencia visual.

La arquitectura debe ser capaz de decidir **qué evidencia adicional necesita consultar**, en lugar de analizar obligatoriamente todas las modalidades en todos los casos.

El sistema debe producir:

* clasificación: legítimo / phishing / incierto;
* nivel de riesgo;
* confianza/calibración;
* evidencias que sustentan la decisión;
* explicación comprensible para el usuario;
* métricas de coste y latencia;
* registro completo del proceso de análisis para investigación.

El software se implementará principalmente como una **extensión de navegador**, respaldada por un **backend de análisis seguro** y un entorno de **sandboxing** para procesar URLs potencialmente maliciosas.

El dominio de estudio será **phishing web**, utilizando el phishing financiero como **principal escenario experimental**, pero sin limitar arquitectónicamente el detector únicamente a bancos.

# 2. PROBLEMA DE INVESTIGACIÓN

El sistema debe responder a este problema:

Los detectores de phishing pueden depender de señales individuales, listas de reputación o análisis estáticos. Esto puede ser insuficiente ante sitios nuevos, páginas modificadas o amenazas diseñadas para evadir determinadas características. Además, analizar todas las modalidades disponibles para cada URL puede aumentar innecesariamente la latencia y el coste.

La investigación debe estudiar si una estrategia de **adquisición adaptativa y progresiva de evidencias multimodales** puede mantener o mejorar el desempeño de detección y robustez, reduciendo al mismo tiempo el coste de análisis.

# 3. PREGUNTA PRINCIPAL DE INVESTIGACIÓN

Diseña el software de forma que permita responder experimentalmente:

"¿Puede la adquisición adaptativa de evidencias multimodales mejorar la efectividad y robustez de la detección de phishing web frente a estrategias de análisis fijo, manteniendo controlados el coste de procesamiento, la latencia y los falsos positivos?"

# 4. HIPÓTESIS

El sistema debe permitir evaluar las siguientes hipótesis:

H1. La incorporación progresiva de evidencias multimodales mejora Precision, Recall y F1 frente a un detector basado únicamente en características de URL.

H2. La adquisición adaptativa reduce el número promedio de análisis costosos por URL frente a una estrategia que procesa todas las modalidades.

H3. La arquitectura mantiene mejor desempeño ante URLs, hosts o campañas no observadas durante el entrenamiento.

H4. La arquitectura multimodal presenta menor degradación frente a perturbaciones adversariales que un detector dependiente de una sola modalidad.

H5. Un mecanismo de abstención reduce decisiones incorrectas en casos de alta incertidumbre.

H6. Una explicación construida a partir de evidencias estructuradas es más trazable y fiel a la decisión que una explicación generada libremente por un LLM.

# 5. CONTRIBUCIÓN CIENTÍFICA QUE DEBE REFLEJAR EL SOFTWARE

No presentes como innovación simplemente:

* usar IA;
* usar Gemini;
* usar LangGraph;
* usar agentes;
* usar una extensión;
* usar SHAP/LIME;
* usar visión artificial.

Estas son tecnologías o mecanismos de implementación.

La contribución debe centrarse en:

1. **adquisición adaptativa de evidencias multimodales**;
2. **decisión bajo incertidumbre con posibilidad de abstención**;
3. **evaluación de generalización ante amenazas no observadas**;
4. **evaluación de robustez frente a perturbaciones adversariales**;
5. **explicaciones trazables y fundamentadas en evidencias estructuradas**;
6. **evaluación conjunta de efectividad, robustez y coste**.

# 6. PRINCIPIO CENTRAL DE LA ARQUITECTURA

NO implementes un pipeline rígido donde todas las modalidades se ejecuten siempre.

La lógica debe ser adaptativa.

Ejemplo:

URL
→ análisis de URL
→ estimación inicial de riesgo/incertidumbre
→ decidir si la evidencia es suficiente
→ si no es suficiente, consultar infraestructura
→ volver a evaluar
→ si continúa la incertidumbre, consultar contenido
→ si continúa la incertidumbre, realizar análisis visual
→ decisión final o abstención.

Ejemplo conceptual:

Caso A:

URL → evidencia suficiente → decisión.

Caso B:

URL → incertidumbre alta → infraestructura → decisión.

Caso C:

URL + infraestructura → incertidumbre alta → HTML → decisión.

Caso D:

URL + infraestructura + HTML → incertidumbre alta → visión → decisión.

El sistema debe registrar:

* qué modalidades consultó;
* en qué orden;
* por qué decidió consultar una modalidad;
* qué evidencia obtuvo;
* cómo cambió la probabilidad/riesgo;
* coste y latencia acumulados;
* decisión final.

# 7. ARQUITECTURA GENERAL

La arquitectura debe estar compuesta por:

## 7.1. Cliente

Extensión para Chrome/Edge basada en Manifest V3.

Responsabilidades:

* detectar la URL navegada;
* enviar la URL al backend;
* recibir resultado;
* mostrar advertencia;
* mostrar riesgo;
* mostrar evidencias;
* mostrar explicación;
* permitir regresar o continuar;
* registrar interacción del usuario para experimentos de usabilidad si se implementa esa fase.

La extensión NO debe realizar directamente operaciones pesadas o peligrosas.

## 7.2. Backend

API REST modular.

Debe contener como mínimo:

* API Gateway;
* orchestrator;
* URL analyzer;
* infrastructure analyzer;
* content analyzer;
* visual analyzer;
* risk/decision engine;
* uncertainty/abstention module;
* explanation engine;
* experiment logger;
* persistence;
* observability.

## 7.3. Sandbox

Las URLs sospechosas deben procesarse en un entorno aislado.

Nunca cargues una URL potencialmente maliciosa directamente en el navegador del usuario para realizar el análisis.

El sandbox debe:

* ejecutar navegador headless;
* aislar procesos;
* limitar acceso a red;
* restringir destinos;
* controlar redirecciones;
* impedir acceso a la infraestructura interna;
* generar screenshot;
* extraer HTML/DOM;
* registrar metadata;
* destruir el entorno después del análisis cuando corresponda.

Diseña medidas contra SSRF, acceso a rangos privados, localhost, metadata endpoints, protocolos no permitidos y redirecciones peligrosas.

## 7.4. Orquestador adaptativo

Utiliza una máquina de estados o un grafo de ejecución explícito.

LangGraph puede utilizarse como herramienta de orquestación, pero NO debe considerarse una contribución científica.

El orquestador debe poder ejecutar agentes/módulos especializados y decidir cuál consultar a continuación.

# 8. MODALIDADES DE ANÁLISIS

## 8.1. URL Analyzer

Extraer características como:

* longitud;
* profundidad;
* número de subdominios;
* caracteres especiales;
* IP en lugar de dominio;
* Punycode;
* homoglyphs;
* leetspeak;
* palabras sospechosas;
* typosquatting;
* combosquatting;
* similitud con dominios legítimos;
* estructura del dominio;
* path;
* query parameters.

Debe evitarse depender exclusivamente de listas de palabras.

Debe existir un registro estructurado de características.

## 8.2. Infrastructure Analyzer

Analizar, cuando sea seguro y técnicamente posible:

* DNS;
* TLS;
* certificado;
* emisor;
* fechas;
* cadena del certificado;
* dominio;
* redirecciones HTTP;
* dominio inicial;
* dominio final;
* número de saltos;
* inconsistencias entre URL visible y destino.

No asumir:

"HTTPS = legítimo".

El certificado debe ser solamente una evidencia.

## 8.3. Content Analyzer

En sandbox:

* HTML;
* DOM;
* formularios;
* inputs;
* campos de credenciales;
* scripts;
* enlaces externos;
* iframes;
* indicadores de login;
* contenido textual;
* formularios de pago;
* patrones sospechosos.

Debe guardarse qué características se utilizaron en la decisión.

## 8.4. Visual Analyzer

A partir de un screenshot generado en sandbox:

* similitud visual;
* estructura de página;
* formularios;
* logotipo;
* distribución;
* elementos de autenticación;
* características visuales relevantes.

No confíes exclusivamente en una comparación por color o logo.

La modalidad visual debe combinar características suficientemente robustas y registrar la métrica de similitud.

# 9. AGENTES/MÓDULOS ESPECIALIZADOS

Puedes usar agentes especializados:

* URL Agent;
* Infrastructure Agent;
* Content Agent;
* Visual Agent;
* Risk/Fusion Agent;
* Explanation Agent.

Sin embargo:

* los agentes NO deben inventar evidencias;
* no deben modificar arbitrariamente datos de otros agentes;
* cada evidencia debe estar estructurada;
* cada resultado debe indicar fuente;
* cada resultado debe registrar timestamp;
* el motor de decisión debe poder reconstruirse sin depender del texto generado por el LLM.

# 10. MODELO DE EVIDENCIA

Diseña una estructura de datos similar a:

{
"analysis_id": "...",
"source": "url|infrastructure|content|visual",
"feature": "...",
"value": "...",
"normalized_value": 0.0,
"reliability": 0.0,
"timestamp": "...",
"contribution": 0.0
}

La decisión debe construirse a partir de esta evidencia estructurada.

El LLM no debe ser la única fuente de verdad.

# 11. MOTOR DE FUSIÓN

Diseña un mecanismo que combine las evidencias y produzca:

* risk_score;
* probability_phishing;
* confidence;
* uncertainty;
* decision;
* evidence_summary.

La estrategia inicial debe ser reproducible y controlable.

No empieces con un sistema completamente opaco.

Puede utilizarse un modelo supervisado, ensemble, score ponderado o arquitectura híbrida, pero debe ser posible explicar cómo se obtuvo la decisión.

# 12. MECANISMO DE ABSTENCIÓN

La salida no debe limitarse a:

* legitimate;
* phishing.

Debe incluir:

* legitimate;
* phishing;
* uncertain.

El sistema debe abstenerse cuando la evidencia sea insuficiente o exista incertidumbre alta.

Los umbrales NO deben inventarse manualmente sin justificación.

Deben calibrarse mediante validation.

Registra:

* threshold;
* confidence;
* uncertainty;
* coverage;
* error rate.

# 13. EXPLICABILIDAD

La explicación debe construirse a partir de evidencia estructurada.

Ejemplo:

RIESGO ALTO

Motivos principales:

1. El dominio presenta similitud con un dominio legítimo.
2. Se detectaron múltiples redirecciones.
3. Existe un formulario de autenticación.
4. La apariencia presenta alta similitud con una entidad conocida.

Nunca generes explicaciones que no puedan trazarse hacia una evidencia registrada.

El LLM puede transformar evidencia técnica en lenguaje natural, pero NO debe introducir nuevos hechos.

# 14. EXTENSIÓN DEL NAVEGADOR

La extensión debe mostrar:

* indicador de riesgo;
* score;
* estado;
* explicación;
* evidencias;
* timestamp;
* opción para regresar;
* opción para continuar bajo advertencia cuando corresponda.

Debe evitarse una interfaz saturada.

Diseño:

* profesional;
* minimalista;
* claro;
* sin gradientes innecesarios;
* centrado en lectura rápida;
* diferenciación visual clara entre riesgo alto, bajo e incierto.

# 15. DATASET

Diseña una pipeline reproducible para obtener y preparar datos.

Phishing:

* PhishTank y/o fuentes académicas/reproducibles;
* otras fuentes públicas solo si su licencia/uso lo permite.

Legítimos:

* Tranco u otra fuente reproducible.

También estudiar la posibilidad de construir un subconjunto específico de phishing financiero.

El dataset debe guardar como mínimo:

* URL;
* etiqueta;
* timestamp;
* dominio/host;
* fuente;
* screenshot cuando exista;
* características extraídas;
* versión del dataset.

No mezclar indiscriminadamente datos muy similares entre train y test.

# 16. PARTICIÓN DEL DATASET

Implementar como mínimo:

## Experimento 1

Split convencional para baseline.

## Experimento 2

Split por dominio/host.

## Experimento 3

Split temporal.

El sistema debe impedir fuga de información entre train y test.

Documentar siempre:

* número de muestras;
* distribución de clases;
* hosts;
* periodo temporal;
* criterios de exclusión.

# 17. BASELINES

Implementar y evaluar como mínimo:

Baseline 1:
URL-only.

Baseline 2:
URL + infraestructura.

Baseline 3:
URL + infraestructura + HTML.

Baseline 4:
todas las modalidades con ejecución fija.

Propuesta:
todas las modalidades + adquisición adaptativa + abstención.

El objetivo es demostrar qué componente aporta valor.

# 18. ABLATION STUDY

Implementar una matriz experimental:

M0 = URL

M1 = URL + infraestructura

M2 = URL + infraestructura + HTML

M3 = URL + infraestructura + HTML + visual

M4 = M3 + adaptación

M5 = M4 + abstención

Registrar rendimiento y coste de cada versión.

# 19. MÉTRICAS DE DETECCIÓN

Como mínimo:

* Accuracy;
* Precision;
* Recall;
* F1;
* Specificity;
* False Positive Rate;
* ROC-AUC;
* PR-AUC.

No depender solo de Accuracy.

# 20. MÉTRICAS OPERATIVAS

Registrar:

* latencia total;
* latencia por modalidad;
* tiempo de sandbox;
* número de modalidades consultadas;
* número de agentes ejecutados;
* llamadas al LLM;
* tokens consumidos;
* coste estimado;
* tasa de timeout;
* tasa de errores.

# 21. MÉTRICAS DE ADAPTACIÓN

Medir:

* porcentaje de URLs resueltas con solo URL;
* porcentaje que requiere infraestructura;
* porcentaje que requiere HTML;
* porcentaje que requiere visión;
* promedio de modalidades utilizadas;
* coste medio por URL;
* latencia media;
* ahorro frente a estrategia fija.

# 22. MÉTRICAS DE ABSTENCIÓN

Medir:

* coverage;
* abstention rate;
* error rate bajo distintos niveles de coverage;
* calibration;
* Expected Calibration Error, si resulta viable.

Construir curvas coverage-risk cuando sea apropiado.

# 23. EXPERIMENTO DE PHISHING NO VISTO

Entrenar con datos anteriores.

Probar con:

* hosts no observados;
* dominios no observados;
* periodo temporal posterior.

Comparar degradación respecto a un conjunto convencional.

# 24. EXPERIMENTO ADVERSARIAL

Crear perturbaciones controladas sobre muestras phishing de investigación.

Ejemplos:

* cambios de caracteres;
* homoglyph;
* leetspeak;
* cambios de path;
* cambios superficiales de HTML;
* modificaciones visuales;
* redirecciones;
* perturbaciones combinadas.

Medir:

* tasa de éxito del ataque;
* caída de Recall;
* caída de F1;
* cambio de confianza;
* cambio de explicación.

No generar campañas reales ni desplegar phishing contra terceros.

Todos los experimentos deben realizarse con datasets y entornos controlados.

# 25. EXPERIMENTO DE EXPLICABILIDAD

Comparar:

A. explicación libre generada por LLM.

B. explicación basada en evidencia estructurada.

Evaluar:

* fidelidad;
* consistencia;
* trazabilidad;
* completitud;
* estabilidad ante pequeñas perturbaciones.

Si se realiza evaluación con usuarios, medir:

* comprensión;
* tiempo de interpretación;
* decisión correcta;
* carga cognitiva o facilidad percibida.

# 26. EVALUACIÓN DEL USUARIO

Solo implementar después de estabilizar el detector.

Diseñar una pequeña evaluación controlada donde los participantes reciban:

* sitios legítimos;
* phishing;
* casos inciertos.

Comparar:

* sin explicación;
* explicación propuesta.

Medir:

* tasa de decisión correcta;
* tiempo;
* comprensión de la razón;
* confianza percibida.

No afirmar que el sistema "educa" al usuario a largo plazo salvo que se realice un estudio longitudinal.

# 27. SEGURIDAD DEL PROPIO SISTEMA

El software debe protegerse contra:

* SSRF;
* acceso a localhost;
* IPs privadas;
* cloud metadata endpoints;
* protocolos no permitidos;
* redirecciones infinitas;
* archivos peligrosos;
* payloads excesivamente grandes;
* consumo excesivo de CPU/memoria;
* prompt injection proveniente del sitio analizado;
* contenido web que intente manipular al LLM.

Las páginas analizadas deben considerarse **datos no confiables**.

Nunca permitas que el contenido de la página dicte libremente acciones del sistema.

# 28. TRAZABILIDAD EXPERIMENTAL

Cada análisis debe guardar:

* analysis_id;
* URL;
* timestamp;
* versión del sistema;
* versión del modelo;
* agentes ejecutados;
* evidencias;
* decisión;
* score;
* confianza;
* incertidumbre;
* latencia;
* coste;
* resultado de cada modalidad.

Esto es obligatorio para poder reproducir los experimentos del artículo.

# 29. OBSERVABILIDAD

Implementa logs estructurados y métricas internas.

No guardar secretos.

Debe existir un modo:

DEVELOPMENT

RESEARCH

PRODUCTION

El modo RESEARCH debe facilitar exportación de resultados a CSV/JSON para análisis estadístico.

# 30. STACK TECNOLÓGICO

Puedes proponer una arquitectura razonable, pero prioriza:

* Python/FastAPI para backend y componentes de ML;
* PostgreSQL para persistencia;
* Redis cuando sea necesario;
* Playwright/Chromium para sandbox;
* extensión Chrome/Edge Manifest V3;
* React/TypeScript si se requiere una interfaz administrativa;
* Docker para aislamiento;
* LangGraph solo si aporta una implementación clara de la orquestación.

No introduzcas tecnologías innecesarias.

No uses una base de datos vectorial si no existe una necesidad real.

No entrenes un LLM desde cero.

Prioriza modelos preentrenados y componentes reproducibles.

# 31. FASES OBLIGATORIAS DEL DESARROLLO

No implementes todo de una vez.

## FASE 0 — Diseño científico

Antes de escribir código:

* define arquitectura;
* variables;
* hipótesis;
* métricas;
* datasets;
* baselines;
* amenazas;
* protocolo experimental;
* criterios de éxito.

Entrega:

* documento de arquitectura;
* diagrama;
* modelo de datos;
* protocolo experimental.

NO programar todavía.

## FASE 1 — Pipeline de datos

Implementar:

* adquisición;
* limpieza;
* deduplicación;
* etiquetado;
* partición;
* versionado.

Entregar:

* dataset procesado;
* estadísticas;
* scripts reproducibles.

## FASE 2 — Baseline URL

Implementar solamente:

URL → características → modelo → clasificación.

Evaluar.

No avanzar hasta obtener baseline reproducible.

## FASE 3 — Infraestructura

Agregar:

TLS + DNS + redirecciones.

Comparar contra baseline.

## FASE 4 — Contenido

Agregar HTML/DOM.

Realizar nueva evaluación.

## FASE 5 — Visual

Agregar screenshot + análisis visual.

Medir coste y rendimiento.

## FASE 6 — Fusión multimodal fija

Procesar todas las modalidades.

Establecer el benchmark multimodal.

## FASE 7 — Orquestación adaptativa

Implementar:

* selección de siguiente modalidad;
* criterio de incertidumbre;
* criterio de parada;
* presupuesto de coste.

Comparar contra FASE 6.

## FASE 8 — Abstención y calibración

Agregar:

* uncertain;
* confidence;
* coverage-risk;
* calibración.

## FASE 9 — Explicabilidad

Agregar:

* evidencia estructurada;
* explicación;
* trazabilidad.

## FASE 10 — Robustez adversarial

Implementar únicamente dentro del entorno experimental.

## FASE 11 — Extensión

Convertir el backend en un cliente de navegación real.

## FASE 12 — Evaluación final

Ejecutar todo el protocolo:

* baseline;
* ablación;
* temporal;
* host-unseen;
* adversarial;
* coste;
* abstención;
* explicabilidad;
* usabilidad, si corresponde.

# 32. REGLAS IMPORTANTES DURANTE EL DESARROLLO

No avances a la siguiente fase si la fase actual no es reproducible.

No ocultes fallos.

No inventes resultados.

No utilices datasets de prueba para ajustar parámetros.

No mezcles train y test.

No reportes Accuracy como única evidencia.

No afirmes que una modalidad "mejora" si no existe comparación experimental.

No afirmes que el sistema detecta zero-day de forma absoluta. Utiliza formulaciones como:

* amenazas no observadas;
* generalización temporal;
* dominios no vistos.

No presentes un LLM como detector infalible.

No permitas que el LLM sea la única autoridad para clasificar una URL.

No envíes URLs maliciosas reales sin control a servicios externos que puedan registrar o interactuar con ellas.

No expongas públicamente un sandbox vulnerable.

No implementes características que no tengan una justificación experimental.

# 33. RESULTADOS QUE EL SISTEMA DEBE PODER GENERAR PARA EL ARTÍCULO

Genera automáticamente:

* tablas de métricas;
* matriz de confusión;
* ROC;
* Precision-Recall;
* F1 por modalidad;
* FPR;
* curvas coverage-risk;
* latencia por modalidad;
* coste por URL;
* número de modalidades consultadas;
* rendimiento temporal;
* rendimiento host-unseen;
* robustez adversarial;
* comparación de explicaciones.

Todos los resultados deben poder exportarse a CSV/JSON.

# 34. CRITERIOS DE ÉXITO

No fijes porcentajes arbitrarios antes de realizar el baseline.

Define éxito de forma comparativa:

La propuesta será considerada favorable si, frente a los baselines apropiados:

* mejora o mantiene F1/Recall;
* reduce falsos positivos;
* presenta menor degradación en escenarios no vistos;
* ofrece mejor relación rendimiento/coste;
* reduce análisis innecesarios mediante adaptación;
* mantiene explicaciones trazables;
* y demuestra comportamiento controlado bajo incertidumbre.

# 35. ENTREGABLES FINALES

El proyecto deberá terminar con:

1. extensión funcional;
2. backend;
3. sandbox;
4. pipeline de datos;
5. modelos;
6. sistema de orquestación;
7. módulo de explicabilidad;
8. módulo de abstención;
9. scripts de evaluación;
10. datasets/versiones utilizados;
11. configuración reproducible;
12. documentación de arquitectura;
13. documentación de seguridad;
14. resultados experimentales;
15. exportaciones para análisis estadístico;
16. README completo;
17. instrucciones de despliegue;
18. instrucciones para reproducir los experimentos.

# 36. FORMA DE TRABAJO DE LA IA

Antes de programar cada fase:

1. explica qué problema científico resuelve;
2. especifica qué componentes se crearán;
3. define entradas y salidas;
4. indica cómo se evaluará;
5. explica qué archivos serán modificados/creados;
6. implementa;
7. ejecuta pruebas;
8. muestra resultados;
9. documenta decisiones;
10. solo después permite pasar a la siguiente fase.

Si detectas que una funcionalidad no aporta valor científico o aumenta innecesariamente la complejidad, señálalo y propón eliminarla.

Si una decisión arquitectónica puede afectar la validez del artículo, debes advertirlo antes de implementarla.

La prioridad es:

**validez experimental > seguridad > reproducibilidad > claridad > funcionalidad > cantidad de características.**

El resultado final debe parecer un **prototipo experimental de investigación en ciberseguridad**, no una aplicación comercial sobrecargada.
