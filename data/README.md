# Datos de investigacion

Los feeds descargados y datasets procesados se excluyen de Git porque pueden
contener URLs activas, tokens en query strings u otros datos sensibles.

## Flujo

```powershell
python -m pip install -e .
python -m phishguard_data fetch --config configs/data-pipeline.example.json
python -m phishguard_data build --config configs/data-pipeline.example.json --snapshot data/raw/<snapshot-id>
```

`fetch` descarga solamente los feeds conocidos declarados en la configuracion.
`build` valida, normaliza, deduplica y particiona sus registros; no abre ninguna URL
incluida dentro de los feeds.

Antes de una adquisicion real se debe fijar el identificador permanente de Tranco
cuando sea posible, usar un User-Agent descriptivo, revisar terminos/licencias y
conservar el manifiesto resultante. Una app key de PhishTank puede incorporarse en
una configuracion local no versionada; nunca debe guardarse en este repositorio.

Para un split temporal se pasan al comando `build` al menos tres snapshots mediante
varios argumentos `--snapshot`. Un solo snapshot genera correctamente los splits
convencional y host-unseen, y marca el temporal como no disponible.
