# Fase 3 - Evidencia de infraestructura

## Problema cientifico

M1 debe medir si DNS, TLS y redirecciones aportan informacion sobre M0 sin convertir
la recoleccion en una fuente de SSRF, fuga temporal o sesgo de disponibilidad. La
modalidad puede fallar o quedar bloqueada; ese resultado debe conservarse y no
transformarse silenciosamente en una feature numerica normal.

## Componentes

- politica de URL, esquema y puerto;
- resolucion A/AAAA y clasificacion de todas las direcciones;
- conexion HTTP(S) a una IP previamente validada y fijada;
- inspeccion de TLS y certificado X.509;
- seguimiento manual y limitado de redirecciones;
- agregacion de features y evidencia estructurada;
- CLI bloqueada fuera del sandbox;
- transportes inyectables para pruebas sin red.

El despliegue reproducible del worker, resolver y proxy se encuentra en
[`sandbox/`](../../sandbox/README.md).

## Entradas

- URL canonicalizada;
- snapshot versionado de Public Suffix List;
- configuracion de limites y politica;
- reloj UTC y dependencias de red inyectables.

## Salidas

`InfrastructureResult` contiene estado, hops, resoluciones, TLS, redirecciones,
features, evidencias, latencia y error tipado. Cada hop registra la URL solicitada,
host, puerto, IP fijada, conjunto completo de IPs resueltas, estado HTTP y metadata
TLS. Del certificado hoja se conserva metadata estructurada y de la cadena solo
huellas SHA-256. Los cuerpos HTTP no se almacenan en esta fase.

## Controles SSRF

1. Solo se permiten HTTP y HTTPS en sus puertos configurados.
2. Se rechazan credenciales de URL para la operacion de red.
3. Se bloquean nombres locales y de metadata antes de DNS.
4. Se validan todas las respuestas IPv4/IPv6; una respuesta mixta invalida el host.
5. Se bloquean direcciones no globales y prefijos de transicion que puedan ocultar
   IPv4, incluidos IPv4-mapped, 6to4, Teredo y NAT64.
6. El transporte recibe la IP validada y nunca vuelve a resolver el hostname.
7. Cada `Location` se resuelve y valida como una solicitud nueva.
8. Se limitan hops, timeout, longitud de URL/cabeceras y ciclos.
9. El despliegue real debe aplicar el mismo bloqueo en proxy/firewall. El control de
   aplicacion no sustituye la politica de red.

La CLI exige `PHISHGUARD_SANDBOX=1`. Esta marca reduce ejecuciones accidentales;
no demuestra aislamiento. El gate exige ademas contenedor sin secretos y reglas de
egreso verificadas.

## Protocolo experimental

La adquisicion se realiza cerca de `observed_at` y conserva el desfase. Se compara
M1 contra el M0 congelado usando las mismas muestras y splits. Los timeouts y
bloqueos permanecen en intention-to-evaluate. Se reportan por separado cobertura
de infraestructura, latencia, errores y rendimiento condicionado a adquisicion
exitosa.

No se consultara retrospectivamente infraestructura actual y se presentara como si
hubiera existido en la fecha historica de la etiqueta.

## Gate de Fase 3

- corpus de bypass SSRF IPv4/IPv6 pasa;
- redirecciones se revalidan y los ciclos se detienen;
- transporte demuestra conexion a IP fijada con SNI/Host originales;
- TLS y certificados se convierten en evidencia reproducible;
- worker aislado y egreso por red se verifican antes de URLs reales;
- captura piloto segura produce un informe de cobertura/coste;
- M1 se evalua contra M0 sin usar test para ajustar features o umbrales.

El estado verificable de estos criterios se registra en
[verification.md](verification.md).
El muestreo previo a la captura se registra en [pilot-plan.md](pilot-plan.md).
El contrato de integración con el modelo está en [m1-feature-contract.md](m1-feature-contract.md).
