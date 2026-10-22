# AUDITORÍA DE SEGURIDAD DEL REPOSITORIO — PHISHPE / PHISHGUARD PRO

**Fecha:** 2026-10-15  
**Auditor:** Investigador de Ciberseguridad Aplicada y Auditor de Seguridad de Software  
**Repositorio:** `D:\Proyects\Seguridad_Informacion`  
**Rama:** `corrections-phase2`  
**Commit auditado:** `058169a78fb50af26bfd3ad9e95e547f782fee1c`  
**Directiva de seguridad:** *No divulgar secretos completos, no realizar reescrituras destructivas sin autorización previa y señalar inequívocamente qué acciones requieren la aprobación expresa del propietario del repositorio.*

---

## 1. Resumen Ejecutivo de Seguridad

La auditoría de seguridad del repositorio examinó exhaustivamente el árbol de trabajo actual, el historial de Git accesible, las configuraciones de empaquetado de la extensión de navegador, las políticas de red del backend, el manejo de variables de entorno y el almacenamiento de datos sensibles.

### Veredicto Global de Seguridad
**ESTADO: RIESGO MEDIO-ALTO (HALLAZGO CRÍTICO DE FIRMA PREEXISTENTE; SISTEMA DE DEFENSA ESTABLE)**
- **Hallazgo Crítico SEC-01:** Exposición directa en el repositorio rastreado por Git de la clave privada RSA de firmado de la extensión Chrome (`extension.pem`) y su binario firmado asociado (`extension.crx`).
- **Hallazgo Medio SEC-02:** Desactivación de verificación de certificados TLS (`verify=False`) durante la adquisición de contenido HTML de páginas web a clasificar en `server.py`, y consultas en texto claro (`http://`) al servicio de geolocalización en `detection_rules.py` (documentado técnicamente como Limitación L12).
- **Hallazgo Medio SEC-03:** Configuración permisiva de Cross-Origin Resource Sharing (`CORS: allow_origins=["*"]`) en el servidor local FastAPI.
- **Hallazgo Positivo SEC-04:** Ausencia total de credenciales externas o tokens de API en texto plano (OpenAI, Anthropic, Google, AWS, GitHub) en los archivos rastreados y en el paquete distribuible de evidencia.
- **Hallazgo Positivo SEC-05:** Validación SSRF estricta implementada en los endpoints críticos del backend (`validate_url_ssrf_safety`), mitigando ataques hacia redes internas o bucles de realimentación hacia localhost.

---

## 2. Hallazgos Detallados de Seguridad

### SEC-01: Exposición de Clave Privada de Firma de la Extensión Chrome (`extension.pem`)
* **Severidad:** **CRÍTICA** (Confidencialidad e Integridad de la Cadena de Suministro).
* **Ubicación:** `D:\Proyects\Seguridad_Informacion\extension.pem` (1,704 bytes).
* **Naturaleza del secreto:** Clave privada RSA estándar formato PEM / PKCS#8.
* **Historial de exposición en Git:**
  - Fue introducida originalmente en el commit `4d50414b5cb7f119875320f5176dd40b10b7ceec` (Fecha: *Sun Sep 20 22:49:49 2026 -0500*, Autor: *Jeac <jeff_20_06@hotmail.com>*), bajo el mensaje *"entrenamiento de modelos M0 y M02 sin secretos"*.
  - Permanece presente en el commit base inmutable `ceb0c9e62ab861ce993bd3a1ec636d4d4b3405b7` y en la rama actual `corrections-phase2`.
  - Archivo binario empaquetado asociado: `extension.crx` (7,415 bytes), también rastreado en Git.
* **Vector de amenaza e impacto:**
  - Cualquier actor con acceso de lectura al repositorio de GitHub obtiene la clave privada utilizada para firmar el paquete CRX.
  - El atacante puede firmar versiones maliciosas de la extensión conservando el mismo ID criptográfico de extensión (`chrome-extension://<id>`).
  - Al compartir el mismo ID, una extensión maliciosa podría acceder a los datos almacenados en `chrome.storage.local` por versiones previas o realizar suplantaciones de la interfaz de advertencia.
* **Estado actual de mitigación en el código:**
  - En la fase previa de corrección (commit `058169a`), la herramienta `scripts/_secret_scan_before_commit.py` reconoció este archivo bajo la categoría `PREEXISTING_DOCUMENTED`, impidiendo que el secreto bloquee el flujo de trabajo interno pero documentándolo formalmente en `LIMITACIONES_RESTANTES.md` (§L11).
  - El empaquetador de evidencia `scripts/phase2j_pack_evidence.py` **excluye estrictamente** `extension.pem` y `extension.crx` del archivo ZIP distribuible (`evidencia_phishpe_definitiva.zip`), evitando su propagación a evaluadores externos.
* **Acción requerida:**
  - Ver sección 3 y el documento adjunto `PLAN_REMEDIACION_SEGURIDAD.md`.

---

### SEC-02: Omisión de Exclusiones Criptográficas en `.gitignore`
* **Severidad:** **MEDIA**.
* **Ubicación:** `.gitignore`.
* **Análisis:**
  - `.gitignore` excluye adecuadamente `.env`, `.env.*`, cachés, binarios compilados y artefactos pesados de datos.
  - Sin embargo, **no contenía reglas genéricas** para ignorar claves privadas o certificados (`*.pem`, `*.key`, `*.pfx`, `*.crx`).
  - Esto posibilitó que `extension.pem` fuera añadido inadvertidamente en el commit de septiembre de 2026 mediante `git add .` o similar.
* **Remediación no destructiva ejecutada en esta fase:**
  - Incorporar reglas explícitas de exclusión en `.gitignore` para bloquear automáticamente cualquier archivo `.pem`, `.key`, `.pfx`, `.p12` o `.crx` en futuros commits.

---

### SEC-03: Desactivación de Verificación TLS y Canales No Cifrados (Limitación L12)
* **Severidad:** **MEDIA**.
* **Ubicación:**
  1. `src/phishguard_api/server.py` (Línea ~540):
     ```python
     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
     resp = requests.get(job.url, timeout=10, verify=False, ...)
     ```
  2. `src/phishguard_ml/detection_rules.py` (Línea ~650):
     ```python
     ctx = ssl.create_default_context()
     ctx.check_hostname = False
     ctx.verify_mode = ssl.CERT_NONE
     # Consulta a geolocalización por HTTP plano:
     conn = http.client.HTTPConnection("ip-api.com", timeout=3)
     ```
* **Impacto y justificación histórica:**
  - *Justificación técnica:* Muchos sitios de phishing operan con certificados SSL vencidos, nombres de host discrepantes o certificados autofirmados. Si el backend abortara la conexión ante un fallo de certificado TLS, no podría descargar el HTML para extraer las características de M2 (formularios de login, inputs de contraseña).
  - *Riesgo de ciberseguridad:* Un intermediario de red (MITM) en el entorno del analizador podría alterar la página inyectando contenido malicioso o falsificando las características enviadas al clasificador.
  - *Fuga de metadatos:* La consulta hacia `ip-api.com` por HTTP plano expone la dirección IP consultada ante observadores pasivos en la red.
* **Estado en la auditoría:**
  - Documentado explícitamente en `LIMITACIONES_RESTANTES.md` (L12). No fue modificado en la rama de correcciones para preservar de forma rigurosa e idéntica las matrices de extracción de características de los modelos congelados M1 y M2.

---

### SEC-04: Variables de Entorno y Manejo de Claves de API
* **Severidad:** **BAJA (Control Satisfactorio)**.
* **Ubicación:** `.env`, `.env.example`, `docker-compose.yml`.
* **Análisis de estado:**
  - El archivo `.env` en disco contiene claves de entorno locales (`POSTGRES_PASSWORD`, `GEMINI_API_KEY`, `GROQ_API_KEY`).
  - `.env` **nunca ha sido versionado ni rastreado en el historial de Git** (verificado mediante `git log --all --full-history -- .env`).
  - `.env.example` contiene únicamente valores ficticios seguros de plantilla (`POSTGRES_PASSWORD=replace-with-a-local-password`).
  - El barrido automatizado de secretos (`scripts/_secret_scan_before_commit.py`) analizó 319 archivos (rastreados + no ignorados) y confirmó:
    * 0 claves AWS (`AKIA...`).
    * 0 tokens GitHub (`ghp_...`, `gho_...`).
    * 0 claves OpenAI (`sk-...`).
    * 0 claves Groq (`gsk_...`).
    * 0 tokens JWT en código fuente.
  - La única coincidencia de patrón de clave Google (`AIzaSy...`) corresponde a un parámetro público OAuth de Firebase incrustado en una URL maliciosa real citada en el reporte de auditoría baseline, no a una credencial de desarrollo.

---

### SEC-05: Aislamiento de Red y Mitigación de SSRF
* **Severidad:** **BAJA (Control Robusto Verificado)**.
* **Ubicación:** `src/phishguard_infra/policy.py`, `src/phishguard_api/server.py`.
* **Mecanismos de protección verificados:**
  - La función `validate_url_ssrf_safety(url)` valida asíncronamente (BUG-02) que las URLs no resuelvan a direcciones IP privadas (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), direcciones de loopback (`127.0.0.0/8`, `::1`), direcciones de enlace local (`169.254.0.0/16`) ni metadatos de computación en la nube (`169.254.169.254`).
  - Se ejecuta en el endpoint síncrono `/check` y en la recuperación de capturas `/screenshots/{filename}`.
  - La suite de tests incluye pruebas específicas de SSRF (`tests/test_infra_policy.py`), confirmando bloqueo inmediato ante vectores de escape.

---

### SEC-06: Configuración de CORS y Exposición de Endpoints
* **Severidad:** **BAJA / INFORMATIVA**.
* **Ubicación:** `src/phishguard_api/server.py` (Líneas 56-61).
* **Análisis:**
  - El middleware CORS está configurado con `allow_origins=["*"]` con un comentario `TODO: Restringir al ID de la extensión Chrome en producción`.
  - Debido a que el backend corre por defecto en `127.0.0.1:8080`, un sitio malicioso abierto en el navegador podría teóricamente enviar peticiones hacia `http://localhost:8080/check`. Sin embargo, gracias a la validación SSRF y a que el endpoint no expone datos de autenticación ni cookies, el impacto está contenido a escaneo de URL local.
  - *Recomendación:* Cuando la extensión tenga un ID de Chrome Web Store definitivo, restringir `allow_origins` a `chrome-extension://<EXTENSION_ID>`.

---

## 3. Matriz de Acciones y Aprobaciones del Propietario

De acuerdo con el rol de auditoría y los principios éticos de intervención de software, se delimita claramente qué acciones se ejecutan de forma autónoma y cuáles **requieren la autorización explícita del propietario del repositorio**:

| Acción de Remediación | Nivel de Riesgo | ¿Ejecutada en esta fase? | ¿Requiere Aprobación Expresa? |
|---|---|---|---|
| **Mejorar `.gitignore` para bloquear `*.pem`, `*.crx`, `*.key`** | Mínimo (No destructivo) | **SÍ (Ejecutada)** | No |
| **Añadir pruebas y scripts de verificación de secretos** | Mínimo (No destructivo) | **SÍ (Ejecutada)** | No |
| **Documentar exposición de `extension.pem` y planes de acción** | Mínimo (No destructivo) | **SÍ (Ejecutada)** | No |
| **Desvincular `extension.pem` y `extension.crx` (`git rm --cached`)** | Medio (Modifica árbol de Git) | Pendiente de aprobación | **SÍ (Requiere Aprobación)** |
| **Generar nuevo par de claves RSA y rotar la extensión** | Medio (Altera ID de extensión) | Pendiente de aprobación | **SÍ (Requiere Aprobación)** |
| **Reescribir historial remoto de Git (`git-filter-repo`)** | Alto (Operación destructiva de Git)| Pendiente de aprobación | **SÍ (Requiere Aprobación)** |
| **Activar `verify=True` en requests de contenido (L12)** | Alto (Afecta extracción de modelos)| Pendiente de aprobación | **SÍ (Requiere Aprobación)** |
| **Borrar modelos o datasets históricos de entrenamiento** | Crítico (Destructivo para reproducibilidad)| **PROHIBIDO / RECHAZADO** | **NO SE PERMITE** |
