# ESTADO DEL ENTORNO DE EJECUCIÓN Y GUÍA DE REPLICACIÓN — PHISHPE

**Fecha de verificación:** 2026-10-15  
**Auditor:** Ingeniero MLOps y Auditor de Reproducibilidad  
**Repositorio:** `D:\Proyects\Seguridad_Informacion`  
**Objetivo:** Documentar con precisión técnica los componentes del hardware, sistema operativo, intérpretes, dependencias y navegadores necesarios para replicar sin discrepancias todos los experimentos y suites de prueba.

---

## 1. Especificaciones de Hardware y Sistema Operativo

| Componente | Especificación Verificada en el Sistema Anfitrión |
|---|---|
| **Sistema Operativo** | Windows 11 Pro 64-bit (Versión: 10.0.26200, Build 26200) |
| **Procesador (CPU)** | 13th Gen Intel(R) Core(TM) i5-13600K (14 núcleos: 6 Performance + 8 Efficient, 20 hilos) |
| **Frecuencia Base** | 3.50 GHz (Turbo hasta 5.10 GHz) |
| **Memoria RAM** | 15.78 GB utilizables (16 GB físicos DDR5/DDR4) |
| **Almacenamiento** | SSD NVMe PCIe 4.0 |
| **Arquitectura** | x86_64 / AMD64 |

---

## 2. Entorno de Python y Gestión de Dependencias

### Intérprete y Rutas
- **Versión de Python:** `3.12.10` (64-bit)
- **Ruta del ejecutable:** `C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe`
- **Gestor de paquetes:** `pip 26.2.1`
- **Modo de instalación del proyecto:** Modo editable local (`pip install -e .` registrado como `phishguard-data 0.1.0` en `D:\Proyects\Seguridad_Informacion`).
- **Archivo de fijación estricta de dependencias:** [`requirements-lock.txt`](file:///d:/Proyects/Seguridad_Informacion/requirements-lock.txt) (336 librerías fijadas con versión exacta).

### Paquetes Principales y Versiones Verificadas

| Paquete | Versión Instalada | Propósito en el Proyecto |
|---|---|---|
| `scikit-learn` | `1.7.2` | Entrenamiento e inferencia de modelos M0, M1, M2, M3, calibración |
| `torch` | `2.12.0` | Inferencia de embeddings y clasificadores basados en tensores |
| `transformers` | `4.57.6` | Modelos de lenguaje y procesamiento de texto |
| `sentence-transformers` | `2.5.1` | Similitud semántica y representaciones vectoriales |
| `fastapi` | `0.111+` | Framework de backend para endpoints síncronos y asíncronos |
| `uvicorn` | `0.53.0` | Servidor ASGI de alto rendimiento para FastAPI |
| `playwright` | `1.64.0` | Automatización de navegador para capturas CDP y pruebas E2E |
| `selenium` | `4.50.0` | Compatibilidad secundaria de crawling web |
| `pytest` | `9.0.3` | Framework de ejecución de pruebas unitarias y de integración |
| `pydantic` | `2.13.5` | Validación de esquemas y contratos de datos |
| `pandas` | `3.0.5` | Manipulación de datasets tabulares y cohortes |
| `numpy` | `2.4.6` | Operaciones matriciales, métricas y cálculo de entropía |
| `Pillow` | `12.3.0` | Procesamiento y extracción de características visuales en imágenes |
| `opencv-python-headless` | `5.0.0.93` | Análisis visual computerizado y detección de bordes |
| `sqlalchemy` | `2.0.23` | ORM asíncrono para base de datos de análisis |
| `asyncpg` | `0.29.0` | Driver de conexión asíncrona a PostgreSQL |
| `cryptography` | `46.0.7` | Operaciones de hashing, certificados y seguridad |
| `joblib` | `1.5+` | Serialización y deserialización de modelos `.joblib` |

---

## 3. Entornos de Navegador y Motor Chromium

El sistema interactúa con dos variantes de Chromium en el entorno local:

1. **Chrome-for-Testing (CfT) — Variante Oficial de Pruebas Automatizadas:**
   - **Versión:** `Chrome/156.0.8078.4` (Build Playwright `chromium-1248`).
   - **Ruta:** `C:\Users\User\AppData\Local\ms-playwright\chromium-1248\chrome-win64\chrome.exe`.
   - **Capacidades:** Admite la carga de extensiones descomprimidas mediante el argumento `--load-extension`, control total mediante Chrome DevTools Protocol (CDP), pila de red real y consola de eventos.
   - **Uso:** Es el entorno donde se ejecutó la batería oficial E2E de 27 escenarios (`scripts/e2e_chrome_phase2.py`).

2. **Google Chrome de Marca Comercial — Producto Instalado en Host:**
   - **Versión:** `155.0.8059.40`.
   - **Restricción de seguridad:** Desde la versión Chromium 137, las compilaciones oficiales comerciales con *Google Chrome Branding* **bloquean** deliberadamente la carga de extensiones por línea de comandos, emitiendo el log registrado:
     `--load-extension is not allowed in Google Chrome, ignoring.` (`artifacts/e2e_chrome/branded_chrome_load_extension.log`).
   - **Impacto documentado:** Requiere empaquetado formal `.crx` o instalación manual mediante la interfaz de usuario `chrome://extensions` (Modo Desarrollador activado).

---

## 4. Infraestructura de Contenedores y Sandboxing

El proyecto define una topología de microservicios aislada en [`docker-compose.yml`](file:///d:/Proyects/Seguridad_Informacion/docker-compose.yml):

- **Base de Datos:** Contenedor `phishguard_db` con imagen `postgres:16-alpine` mapeado en `127.0.0.1:5433` (evitando conflictos con el puerto 5432 estándar).
- **Backend API:** Contenedor `phishguard_api` exponiendo Uvicorn en `127.0.0.1:8080`.
- **Servidor DNS Seguro:** Contenedor `dns-resolver` corriendo `coredns/coredns:1.14.7` con usuario sin privilegios (`65532`), capacidades mínimas (`NET_BIND_SERVICE`), memoria limitada a 64 MB y CPU a 0.25 núcleos.
- **Proxy de Salida Seguro:** Contenedor `egress-proxy` corriendo `ubuntu/squid:6.6-24.04_edge` en solo lectura con usuario no privilegiado (`13:13`) para filtrar dominios y prevenir accesos indebidos.
- **Red Aislada:** Red interna Docker `phishguard_browser_internal` (`172.31.0.0/24`, `internal: true`), impidiendo que el navegador acceda a la red local anfitriona sin pasar por el proxy.

---

## 5. Guía de Replicación para Evaluadores Externos

Para replicar el entorno en un equipo limpio:

```bash
# 1. Clonar el repositorio
git clone https://github.com/tommy260803/Seguridad_Informacion.git
cd Seguridad_Informacion
git checkout corrections-phase2

# 2. Configurar entorno virtual con Python 3.12
python -m venv .venv
# Activar entorno (Windows):
.\.venv\Scripts\Activate.ps1
# (Linux/macOS): source .venv/bin/activate

# 3. Instalar dependencias exactas
pip install --upgrade pip
pip install -r requirements-lock.txt
pip install -e .

# 4. Instalar binarios de navegador de Playwright
playwright install chromium

# 5. Ejecutar suite de pruebas de validación
pytest -q

# 6. Ejecutar revalidación offline determinista
python scripts/phase2n_revalidate_offline.py
```
*Tiempo estimado de instalación y verificación completa: 4 a 6 minutos.*
