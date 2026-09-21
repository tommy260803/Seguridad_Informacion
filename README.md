# Plataforma experimental de deteccion adaptativa de phishing

Este repositorio contiene el diseno y, en fases posteriores, la implementacion de
un prototipo experimental para deteccion explicable de phishing web mediante
adquisicion adaptativa de evidencia multimodal.

## Estado

**Fase actual: 12 - Evaluación final y exportación.**

La Fase 0 definio el diseno cientifico. La Fase 1 implemento y ejecuto la adquisicion
y preparacion reproducible de datos. La Fase 2 construyo y evaluo el baseline
URL-only. La Fase 3 incorpora adquisicion controlada de DNS, redirecciones y TLS;
su contrato figura en [docs/phase-3/README.md](docs/phase-3/README.md).

La Fase 4 tiene un extractor HTML/DOM offline y el entrenador M2 que combina
URL, infraestructura y contenido. La Fase 5 añade el extractor visual acotado y
la Fase 6 incorpora el benchmark fijo M3 y la Fase 7 añade la política
adaptativa, la Fase 8 añade abstención/calibración, la Fase 9 explicabilidad y
la Fase 10 robustez adversarial controlada, la Fase 11 añade la extensión
Manifest V3 y la Fase 12 incorpora la evaluación final reproducible;
el alcance y gate están en
[docs/phase-4/README.md](docs/phase-4/README.md).
El siguiente entregable científico es comparar M1 contra M0 usando el piloto
autorizado y sus mismos splits congelados.

## Ejecución local (Docker)

### Requisitos previos

- Docker Desktop instalado y en ejecución
- Al menos 4 GB de RAM disponible para Docker
- Puertos 8080, 5433, 53 y 3128 libres

### Pasos

1. **Clonar el repositorio** (si no está hecho):
   ```bash
   git clone <url-del-repositorio>
   cd Seguridad_Informacion
   ```

2. **Crear archivo de variables de entorno**:
   ```bash
   cp .env.example .env
   ```
   Edita el archivo `.env` y establece una contraseña segura para PostgreSQL:
   ```
   POSTGRES_PASSWORD=tu-contraseña-segura
   ```

3. **Construir imagen de Playwright** (necesaria para sandbox aislado):
   ```bash
   docker compose --profile sandbox-build build playwright-image
   ```

4. **Levantar todos los servicios**:
   ```bash
   docker compose up -d --build
   ```

5. **Verificar que los servicios estén corriendo**:
   ```bash
   docker compose ps
   ```
   Deberías ver 4 contenedores:
   - `phishguard_api` (puerto 8080)
   - `phishguard_db` (puerto 5433)
   - `dns-resolver` (puerto 53)
   - `egress-proxy` (puerto 3128)

6. **Probar la API**:
   ```bash
   # Health check
   curl http://127.0.0.1:8080/health

   # Enviar análisis
   curl -X POST http://127.0.0.1:8080/analyses \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'

   # Dashboard web
   # Abrir en navegador: http://127.0.0.1:8080/dashboard
   ```

### Servicios incluidos

| Servicio | Descripción | Puerto |
|----------|-------------|--------|
| `api` | Backend FastAPI + worker asíncrono | 8080 → 8000 |
| `db` | PostgreSQL 16 (datos persistentes) | 5433 → 5432 |
| `sandbox_manager` | Gestor de sandboxes aislados | - |
| `dns-resolver` | CoreDNS para resolución interna | 53 |
| `egress-proxy` | Squid proxy de egreso | 3128 |

### Detener servicios

```bash
docker compose down
```

### Limpiar datos y volúmenes

```bash
docker compose down -v  # Elimina volúmenes de datos
```

## Documentos de la Fase 0

- [Indice y decisiones](docs/phase-0/README.md)
- [Diseno cientifico](docs/phase-0/scientific-design.md)
- [Arquitectura](docs/phase-0/architecture.md)
- [Modelo de datos](docs/phase-0/data-model.md)
- [Modelo de amenazas](docs/phase-0/threat-model.md)
- [Protocolo experimental](docs/phase-0/experimental-protocol.md)

## Principio rector

La validez experimental tiene prioridad sobre la seguridad, la reproducibilidad,
la claridad, la funcionalidad y la cantidad de caracteristicas, en ese orden. Las
paginas analizadas se consideran datos hostiles y ninguna salida generada por un
LLM participa como fuente de verdad en la clasificacion.
