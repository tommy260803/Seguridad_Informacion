# Comparacion M0/M1

El comando `phishcompare` recibe dos directorios de artefactos ya entrenados y
produce un JSON con F1, Recall, precision, FPR, PR-AUC, ROC-AUC, Brier y ECE para
`train`, `validation` y `test`. Cada entrada incluye el delta `M1 - M0`.

Antes de calcular resultados exige que ambos artefactos compartan el hash de
`samples.csv` y del split. El reporte declara que `test` no participa en seleccion;
la seleccion y el umbral deben estar congelados previamente en los artefactos.

Ejemplo:

```powershell
phishcompare --m0 artifacts/url-baseline-0.1.0/conventional-final `
  --m1 artifacts/m1-infrastructure-0.1.0/conventional `
  --output artifacts/m1-infrastructure-0.1.0/comparison.json
```
