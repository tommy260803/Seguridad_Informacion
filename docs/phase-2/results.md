# Resultados del baseline URL-only

## Corrida primaria: authority-only

Dataset `0.1.0`, extractor `url-features-1.0.0`, experimento
`url-baseline-0.2.0`. Este perfil usa 11 features del host y dominio, excluyendo
esquema, path, query y tokens de la URL completa.

En ambos splits se selecciono `histgb-31-sigmoid` por PR-AUC en la particion
`validation-selection`. El calibrador uso dominios distintos de los empleados para
seleccionar candidato y umbral.

| Metrica de test | Convencional | Host-unseen | Delta host-unseen |
|---|---:|---:|---:|
| F1 | 0.916285 | 0.868567 | -0.047718 |
| Recall | 0.888039 | 0.805277 | -0.082762 |
| Precision | 0.946387 | 0.942654 | -0.003733 |
| FPR | 0.038136 | 0.037136 | -0.001000 |
| PR-AUC | 0.967688 | 0.941153 | -0.026535 |
| ROC-AUC | 0.964251 | 0.930802 | -0.033449 |
| Brier score | 0.057897 | 0.081860 | +0.023962 |
| ECE | 0.017707 | 0.015048 | -0.002660 |

Umbral convencional: `0.3193374101`. Matriz: TN 14,427; FP 572; FN 1,273;
TP 10,097.

Umbral host-unseen: `0.4166229286`. Matriz: TN 14,442; FP 557; FN 2,214;
TP 9,156.

La perdida de Recall y PR-AUC indica degradacion relevante ante dominios no vistos.
Es el baseline conservador contra el que deben compararse las modalidades futuras.
No prueba todavia H3, que requiere la serie temporal y la arquitectura multimodal.

## Diagnostico full-URL

El perfil `full_url` produjo F1 0.986246 en convencional y 0.972287 en host-unseen.
No se adopta como resultado primario: Tranco solo aporta dominios, por lo que sus
negativos se materializaron como `https://dominio/`, mientras PhishTank contiene
paths y queries reales. El modelo puede aprender esa diferencia de recoleccion.

La brecha entre perfiles es evidencia de un artefacto de dataset, no de una mejora
del detector. Antes de usar full-URL como baseline principal se integrara un corpus
benigno con URLs completas. PhiUSIIL es candidato externo porque UCI publica URLs y
etiquetas bajo CC BY 4.0, pero se evaluara como dataset separado para no mezclar
fuentes de forma opaca: [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bwebsite%2Bdataset).

## Reproducibilidad

Cada corrida se repitio desde el cache de features verificado. Las predicciones
fueron identicas byte por byte:

- convencional: `205201ee5dfd1a9e44efe9c894870c0b48d6848d343758595e9b3252817e5a49`;
- host-unseen: `6250fe2859a785fa053ec22cbe8349fea6689d94d80d9882c54f6b76b740f2a3`.

Los manifiestos incluyen hashes del dataset, split, cache, configuracion, codigo y
artefactos; versiones de Python, NumPy y scikit-learn; semilla y limite de hilos.
Las salidas completas estan bajo `artifacts/url-baseline-0.2.0/` y permanecen fuera
de Git por contener predicciones a nivel de muestra.

## Limitaciones pendientes

- un solo snapshot impide evaluar generalizacion temporal;
- las etiquetas provienen de fuentes distintas y pueden conservar sesgos de origen;
- Tranco no garantiza que cada dominio sea benigno;
- falta auditoria manual estratificada de etiquetas y conflictos;
- el perfil authority-only no mide señales de path/query;
- no se calcularon intervalos de confianza agrupados en esta corrida inicial.
