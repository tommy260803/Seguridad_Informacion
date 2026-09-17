# Verificacion de Fase 3

Fecha: 2026-09-16

## Alcance implementado

- politica estricta de URL, esquemas y puertos;
- bloqueo de nombres locales, metadata y direcciones IPv4/IPv6 no publicas;
- rechazo de respuestas DNS mixtas y fijacion determinista de IP;
- conexion a IP fijada conservando Host/SNI;
- seguimiento manual de redirecciones, revalidacion por hop, limite y ciclos;
- extraccion de DNS, HTTP, TLS, certificado hoja y huellas de cadena;
- resultados/evidencias estructurados y errores tipados;
- CLI cerrada por defecto fuera del marcador de sandbox.

## Evidencia automatizada

Comando:

```powershell
python -m pytest --basetemp data/cache/pytest
```

Resultado: `100 passed`.

La suite cubre el corpus SSRF, respuestas DNS mixtas, redirecciones a destinos
privados, ciclos, limites, pinning de IP, SNI, certificados, cadena TLS,
configuracion estricta y bloqueo de la CLI. `compileall` tambien finalizo sin
errores.

El adaptador M1 añade cobertura de estados `success`/`blocked`/`error`, ausencia
explícita, validación de resultados JSONL y matrices ordenadas.

## Gate

| Criterio | Estado | Evidencia |
|---|---|---|
| Corpus SSRF IPv4/IPv6 | Pasa | Tests de politica |
| Revalidacion de redirecciones y ciclos | Pasa | Tests del analizador |
| IP fijada con SNI/Host original | Pasa en unidad | Tests del transporte |
| TLS/certificado reproducible | Pasa en unidad | Metadata y huellas SHA-256 |
| Worker aislado y egreso verificado | Pasa | Inspeccion de runtime y pruebas de red |
| Smoke test real controlado | Pasa | `example.com`, resultado `success` |
| Plan representativo del piloto | Pasa | 24 dominios, cuatro estratos balanceados |
| Captura de cobertura/coste | Pendiente | Espera autorizacion de adquisicion |
| Evaluacion M1 contra M0 | Pendiente | Requiere captura piloto temporalmente valida |

## Verificacion de runtime

Motor: Docker `29.4.0`.

- una conexion directa del worker a `1.1.1.1:443` fallo con `OSError`;
- una solicitud al proxy hacia `127.0.0.1:80` recibio HTTP `403`;
- el worker efectivo uso UID/GID `65532`, rootfs de solo lectura, `CapDrop=ALL`,
  `no-new-privileges`, 32 PIDs, 256 MiB y 0.5 CPU;
- el worker pertenecio solo a `sandbox_internal`, una red sin gateway externo;
- el resolver y el proxy se ejecutaron como usuarios no root;
- el smoke test controlado produjo HTTP `200`, TLS 1.3 verificado, cuatro
  direcciones DNS, cadena TLS de longitud cuatro y 295.69 ms totales.

Imagenes externas verificadas:

- `python:3.13.15-slim-bookworm@sha256:ed86c822...`;
- `coredns/coredns:1.14.7@sha256:7efd3c635...`;
- `ubuntu/squid:6.6-24.04_edge@sha256:8a3baed47...`.

La variable `PHISHGUARD_SANDBOX=1` sigue siendo solo un seguro operacional. La
garantia se apoya en la red interna y los sidecars de DNS/egreso. La Fase 3
permanece abierta hasta ejecutar un piloto representativo y evaluar M1 contra el
M0 congelado; el smoke test no se presenta como resultado experimental.

El plan congelado y su identidad se documentan en [pilot-plan.md](pilot-plan.md).
