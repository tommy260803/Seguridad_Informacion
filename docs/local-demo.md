# Demo local

El backend local es deliberadamente seguro y limitado: no hace DNS, HTTP,
redirecciones, HTML ni screenshots. Solo calcula el baseline URL sobre la cadena
recibida y devuelve una respuesta trazable para probar la extensión.

En PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m phishguard_api.server --host 127.0.0.1 --port 8000
```

Luego carga `extension/` como extensión descomprimida y pulsa **Analizar pestaña**.
