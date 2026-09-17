# Sandbox de infraestructura

Este despliegue separa el worker de Internet mediante una red Docker `internal`.
El worker solo puede consultar al resolver DNS y al proxy de egreso. Squid recibe
la IP que la aplicacion ya valido, aplica una segunda lista de bloqueo y permite
unicamente HTTP/80 y CONNECT/443.

## Controles

- worker no root, rootfs de solo lectura y todas las capabilities eliminadas;
- limites de CPU, RAM, PIDs y filesystem temporal;
- sin puertos publicados, secretos ni socket Docker;
- DNS dedicado con unicamente `NET_BIND_SERVICE`;
- proxy no root, sin cache y con politica default-deny;
- imagenes externas y base del worker fijadas por digest;
- URL de entrada montada como archivo de solo lectura.

## Ejecucion controlada

```powershell
$env:PSL_PATH = (Resolve-Path 'data/raw/<snapshot>/public_suffix_list.dat').Path
$env:TARGET_URL_FILE = (Resolve-Path 'sandbox/target-url.example.txt').Path
$env:OUTPUT_DIR = (Join-Path (Get-Location) 'artifacts/infra-pilot')
New-Item -ItemType Directory -Force $env:OUTPUT_DIR | Out-Null
docker compose -f sandbox/compose.yaml build infrastructure-worker
docker compose -f sandbox/compose.yaml up -d dns-resolver egress-proxy
docker compose -f sandbox/compose.yaml run --rm --no-deps infrastructure-worker
docker compose -f sandbox/compose.yaml down
```

Para muestras reales, el archivo de URL debe permanecer fuera de Git y tener una
sola linea. El resultado contiene la URL completa y debe tratarse como dato de
investigacion restringido.

## Piloto por lotes

Primero se genera y revisa el plan sin red:

```powershell
$env:PYTHONPATH = 'src'
python -m phishguard_infra.batch_cli --plan-only `
  --pilot-config configs/infrastructure-pilot.example.json `
  --dataset data/processed/0.1.0 `
  --output artifacts/infrastructure-pilot-0.1.0
```

La captura requiere autorizacion para contactar los destinos seleccionados. Cuando
exista, se configuran `PSL_PATH`, `DATASET_PATH` y `PILOT_OUTPUT_DIR`, se levantan
los sidecars y se ejecuta `infrastructure-pilot`. El runner guarda cada resultado
antes de continuar y una segunda ejecucion reanuda solo las muestras pendientes.

```powershell
docker compose -f sandbox/compose.yaml up -d dns-resolver egress-proxy
docker compose -f sandbox/compose.yaml run --rm --no-deps infrastructure-pilot
docker compose -f sandbox/compose.yaml down
```
