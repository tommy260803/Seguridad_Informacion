# Contrato de features M1

`phishguard_ml.infrastructure` transforma cada resultado JSONL del analizador en
`infra-features-1.0.0`, un vector numerico fijo de 18 señales. Incluye DNS,
redirecciones, TLS, certificado, estado HTTP y latencias.

La primera parte del vector codifica disponibilidad explícita:

- `infra_observation_available=1` solo para `success`;
- `infra_status_success`, `infra_status_blocked` e `infra_status_error` son
  indicadores mutuamente excluyentes;
- una muestra sin resultado conserva todos esos indicadores en cero;
- los valores medidos de una adquisición fallida no se imputan como evidencia
  exitosa.

`infrastructure_feature_matrix(sample_ids, results_path)` respeta el orden de los
IDs solicitado, rechaza resultados duplicados o no finitos y permite combinar una
captura parcial con el dataset congelado. La selección de modelo, calibración y
umbral de M1 se hará únicamente con `train`/`validation`; `test` permanece reservado.
