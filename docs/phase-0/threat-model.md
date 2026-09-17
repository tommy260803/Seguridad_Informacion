# Modelo de amenazas

## Alcance y supuestos

La URL, DNS, certificados, cabeceras, HTML, scripts, imagenes y texto de una pagina
son entrada hostil. Un atacante controla dominios, redirecciones, tiempos, volumen
y contenido, y puede intentar atacar el analizador o sesgar el modelo. El sistema
no asume que HTTPS, un certificado valido o una marca visual impliquen legitimidad.

## Activos

- red interna, host, metadata cloud y servicios de control;
- secretos, credenciales y datos de usuarios/investigacion;
- integridad de etiquetas, features, modelos y resultados;
- disponibilidad de workers y presupuesto;
- confidencialidad de muestras y artefactos;
- trazabilidad de decisiones y reproducibilidad.

## Fronteras

1. Extension a API publica.
2. API/orquestador a cola y persistencia.
3. Control plane a worker sandbox.
4. Sandbox a Internet mediante proxy.
5. Artefactos hostiles a extractores y, opcionalmente, al LLM.

## Matriz de amenazas y controles

| Amenaza | Control preventivo | Evidencia de verificacion |
|---|---|---|
| SSRF a localhost/red privada/metadata | Solo HTTP(S), parser estricto, A/AAAA publicas, proxy de egreso, bloqueo de rangos especiales IPv4/IPv6 | Tests con corpus de bypass y reglas de red |
| DNS rebinding/pinning | Resolver en proxy, validar todas las respuestas y conectar a IP fijada; revalidar cada salto | Test DNS controlado con cambio de respuesta |
| Redireccion peligrosa o ciclo | Redirect manual, revalidacion completa, limite de saltos y dominios, deteccion de ciclo | Tests multi-hop, privado y loop |
| Protocol smuggling | Allowlist de esquemas y puertos; rechazar userinfo, URLs ambiguas y formas IP alternativas | Tests de parser diferencial |
| Escape del navegador | Contenedor efimero sin privilegios, seccomp, usuario no root, filesystem read-only, sin socket/secretos | Inspeccion de runtime y prueba de aislamiento |
| Agotamiento de recursos | Timeout, limites de CPU/RAM/PIDs/bytes/respuestas/DOM, cuota por cliente y circuit breaker | Pruebas con pagina lenta y payload grande |
| Descarga/archivo peligroso | Bloquear descargas, no abrir adjuntos, validar MIME, almacenar como blob no ejecutable | Tests de Content-Disposition/MIME |
| Prompt injection web | Nunca tratar contenido como instrucciones; esquema de salida cerrado; LLM sin herramientas ni red; allowlist de evidence IDs | Corpus de inyeccion y verificador de grounding |
| Exfiltracion via subrecursos | Proxy sin secretos, cabeceras/cookies limpias, bloqueo de puertos, limites y registro de destinos | Inspeccion de request headers y destinos |
| Contaminacion del dataset | Proveniencia, hashes, snapshots, deduplicacion por URL/host/contenido y revision de etiquetas | Informe de calidad y leakage audit |
| Envenenamiento de modelos | Fuentes permitidas, artefactos inmutables, firma/hash y separacion de roles | Verificacion de manifiestos |
| Evasion multimodal | Perturbaciones controladas, señales cruzadas y abstencion | Experimento adversarial preespecificado |
| Fuga por logs/exportaciones | Redaccion, IDs correlacionables, cifrado, acceso por rol y retencion | Tests de redaccion y auditoria de exportacion |
| Extension comprometida | Permisos minimos MV3, CSP estricta, sin codigo remoto, mensajes validados | Revision de manifest y pruebas de mensajes |
| Abuso de API | Autenticacion, rate limit, cuotas, tamanos maximos e idempotencia | Pruebas de carga y autorizacion |

## Politica de red del sandbox

El analisis rechaza esquemas distintos de `http` y `https`. Antes de cada conexion,
incluidas redirecciones y subrecursos, el proxy valida todas las direcciones A/AAAA
y bloquea loopback, privadas, link-local, multicast, reservadas, no especificadas,
documentation ranges y endpoints de metadata conocidos. Se aplican controles tanto
en aplicacion como en la red; una validacion correcta no sustituye el aislamiento.

La navegacion no hereda cookies, autenticacion, proxy corporativo ni cabeceras del
usuario. No envia formularios, no concede permisos, no descarga archivos y limita
subrecursos. Los limites concretos se fijaran por configuracion y se probaran antes
de capturar muestras reales.

## Seguridad del contenido y del LLM

Los parsers operan sobre copias con limites. El texto web se etiqueta como dato no
confiable. Si una fase posterior incorpora un LLM, recibira una seleccion de campos
estructurados, sin JavaScript, instrucciones embebidas ni herramientas. Su salida
debe validar contra un esquema que solo permita parafrasear `evidence_id` existentes;
si falla, se usa una plantilla determinista.

## Manejo de muestras

La captura real se realiza solo con autorizacion institucional aplicable y desde
infraestructura dedicada. No se introducen credenciales, no se intenta completar
flujos de pago y no se publican URLs activas. Los experimentos adversariales usan
copias locales o fixtures inertes, sin desplegar campanas ni contactar terceros.

## Criterios de bloqueo antes de Fase 4

No se habilita adquisicion HTML/visual de Internet hasta demostrar: bloqueo SSRF
IPv4/IPv6 y redirecciones, aislamiento del worker, limites de recursos, ausencia de
secretos, eliminacion del entorno y registro reproducible. Los fallos de seguridad
cierran el worker y producen `blocked`/`error`; nunca fuerzan una clasificacion.

## Referencias de control

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [Chrome Extensions security guidance](https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure)
