# Plan del piloto de infraestructura

Fecha de congelacion: 2026-09-16

El piloto `infrastructure-pilot-0.1.0` usa el split `conventional` y selecciona 24
muestras sin reemplazo. No incluye `test`, limita cada dominio registrable a una
muestra y aplica una pausa de un segundo entre adquisiciones.

## Composicion

| Estrato | Muestras |
|---|---:|
| train / legitimate / constructed_from_domain | 6 |
| train / phishing / reported_url | 6 |
| validation / legitimate / constructed_from_domain | 6 |
| validation / phishing / reported_url | 6 |

Total: 24 muestras y 24 dominios registrables unicos.

## Identidad

- plan SHA-256: `dd390bb3eac15ce985e0b1fe52c4d684a98ce3ff5bbd6f9d79a8331b7f6f9541`;
- configuracion SHA-256: `a50ffb523976946ba49512a35c48f3dce82ac2a03da1751e73f30223717e27c7`;
- `samples.csv` SHA-256: `788092eef6a56c94ce4de32ec98570415ec06049776a20ba6699d7c101eb70c8`;
- split SHA-256: `f5e47f164396ff4161946a0923dba366650660e182604240a01e7a54537fba22`.

El plan contiene URLs activas y permanece en `artifacts/`, fuera de Git. El resumen
no contiene URLs. La adquisicion no se ejecuta hasta contar con autorizacion para
contactar los destinos reportados como phishing. Generar el plan no realiza red.

