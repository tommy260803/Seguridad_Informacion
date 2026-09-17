# Fase 11 - Extensión Manifest V3

`extension/` contiene un cliente Chrome/Edge sin dependencias externas. El
service worker obtiene la URL de la pestaña y reenvía únicamente esa URL al
backend configurado; no ejecuta analizadores, descarga HTML ni toma screenshots.
El popup presenta decisión, probabilidad y hasta cinco evidencias recibidas.

El endpoint por defecto es `http://localhost:8000/analyze` y puede cambiarse en
la interfaz. La extensión está orientada al entorno de investigación local; no
se declara lista para producción hasta añadir autenticación, CORS restringido y
políticas de despliegue.
