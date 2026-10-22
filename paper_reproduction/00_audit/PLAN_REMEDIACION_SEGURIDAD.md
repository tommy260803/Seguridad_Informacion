# PLAN DE REMEDIACIÓN DE SEGURIDAD — PHISHPE / PHISHGUARD PRO

**Fecha:** 2026-10-15  
**Elaborado por:** Arquitecto Senior de Software y Auditor de Ciberseguridad Aplicada  
**Documento de referencia:** `AUDITORIA_SEGURIDAD.md`  
**Objetivo:** Establecer los procedimientos operativos paso a paso para la rotación de credenciales expuestas, saneamiento de repositorios y hardening de seguridad, sin comprometer la reproducibilidad científica ni alterar de manera destructiva el historial sin aprobación previa.

---

## 1. Alcance y Principios Rectores

Este plan define las fases de remediación para los riesgos identificados durante la auditoría de seguridad.  
Se rige por tres principios inquebrantables:
1. **Preservación de la reproducibilidad científica:** Los modelos, datasets, umbrales y semillas congeladas no deben alterarse silenciosamente.
2. **No repudiación y trazabilidad:** Toda modificación en el historial de Git debe ser planificada, respaldada y explícitamente autorizada por el propietario del repositorio.
3. **Mínimo privilegio y defensa en profundidad:** Ninguna credencial privada debe volver a ingresar a un árbol rastreado por Git.

---

## 2. Procedimiento Operativo: Remediación de `extension.pem` y `extension.crx`

### Diagnóstico Actual
- Archivos afectados: `extension.pem` (clave RSA privada) y `extension.crx` (archivo empaquetado firmado con dicha clave).
- Estado en Git: Rastreados en Git desde el commit `4d50414b` (2026-09-20) y presentes en `main`, `corrections-phase2` y `experimental/validacion-scopus-fase2`.
- Riesgo: Firma apócrifa de la extensión por actores no autorizados.

---

### Fase A: Blindaje Preventivo Inmediato (Ejecutado)
*Acción no destructiva sin impacto en el historial existente.*

1. **Actualización de `.gitignore`:**
   Añadir al final del archivo `.gitignore` del proyecto las siguientes reglas de exclusión:
   ```gitignore
   # Archivos criptográficos y claves privadas sensibles (Auditoría Seguridad 2026-10)
   *.pem
   *.key
   *.pfx
   *.p12
   *.crt
   *.csr
   *.crx
   ```
2. **Verificación de pre-commit:**
   Asegurar que `scripts/_secret_scan_before_commit.py` mantenga la detección activa en cualquier archivo antes de autorizar un commit.

---

### Fase B: Rotación de Clave y Desvinculación de Git (Requiere Aprobación)
*Esta fase genera un nuevo par de claves criptográficas y retira la clave expuesta del árbol de trabajo sin reescribir aún el historial antiguo.*

#### Paso 1: Generación de Nuevo Par de Claves Privada / Pública
Ejecutar en una terminal segura fuera del directorio rastreado:
```bash
# 1. Generar nueva clave privada RSA 2048-bit
openssl genrsa -out extension_private_new.pem 2048

# 2. Extraer la clave pública en formato DER/PKCS#8
openssl rsa -in extension_private_new.pem -pubout -outform DER -out extension_pub.der

# 3. Calcular el nuevo Extension ID de Chrome (hash SHA-256 de la clave pública, mapeado a letras a-p)
# (Chrome calcula el ID como los primeros 128 bits de sha256(der_pub) codificados en base16 con alfabeto a-p)
python -c "
import hashlib
with open('extension_pub.der', 'rb') as f:
    digest = hashlib.sha256(f.read()).hexdigest()[:32]
extension_id = ''.join(chr(ord('a') + int(c, 16)) for c in digest)
print(f'Nuevo Extension ID: {extension_id}')
"
```

#### Paso 2: Desvincular archivos de Git sin borrarlos del disco local
```bash
# Retirar extension.pem y extension.crx del índice de Git sin borrar los archivos locales
git rm --cached extension.pem
git rm --cached extension.crx

# Realizar commit del retiro
git commit -m "security: desvincular extension.pem y extension.crx del seguimiento de Git (SEC-01)"
```

#### Paso 3: Empaquetar y Firmar la Nueva Extensión
Al compilar la extensión para distribución:
```bash
# Empaquetar en Chrome / Chromium usando la nueva clave privada
chrome.exe --pack-extension="d:\Proyects\Seguridad_Informacion\extension" --pack-extension-key="extension_private_new.pem"
```
*Guardar `extension_private_new.pem` en un gestor de secretos de desarrollo seguro (ej. 1Password, Keepass, o variables de CI en GitHub Secrets), NUNCA en la carpeta del repositorio.*

---

### Fase C: Saneamiento Completo del Historial de Git (Requiere Aprobación del Propietario)
*ADVERTENCIA: Esta operación reescribe los hashes SHA de los commits de Git. Requiere coordinación de todo el equipo de desarrollo y un `git push --force` coordinado.*

#### Herramienta Recomendada: `git-filter-repo` (oficial de Git)
1. **Crear un respaldo espejo completo del repositorio:**
   ```bash
   git clone --mirror d:\Proyects\Seguridad_Informacion d:\Proyects\Seguridad_Informacion_BACKUP.git
   ```

2. **Ejecutar purga del archivo en todo el árbol y ramas:**
   ```bash
   # Instalar git-filter-repo (vía pip si es necesario)
   pip install git-filter-repo

   # En el repositorio de trabajo:
   git-filter-repo --path extension.pem --path extension.crx --invert-paths --force
   ```

3. **Verificar que ningún commit contenga ya el archivo:**
   ```bash
   git log --all --full-history -- "extension.pem"
   # El resultado debe ser completamente vacío.
   ```

4. **Sincronización remota forzada (Únicamente tras aprobación expresa):**
   ```bash
   git remote add origin https://github.com/tommy260803/Seguridad_Informacion.git
   git push origin --force --all
   git push origin --force --tags
   ```

---

## 3. Procedimiento Operativo: Hardening de TLS y Red (Limitación L12)

### Diagnóstico Actual
- `server.py` utiliza `requests.get(..., verify=False)`.
- `detection_rules.py` utiliza `http.client.HTTPConnection("ip-api.com")`.

### Solución Arquitectónica Recomendada
Para no romper las evaluaciones históricas congeladas, los cambios de red deben desplegarse bajo un interruptor de configuración (*feature flag*):

1. **Configuración en `phishguard_common/environment.py`:**
   ```python
   # Variable de entorno para controlar la verificación estricta de TLS
   PHISHGUARD_STRICT_TLS: bool = os.getenv("PHISHGUARD_STRICT_TLS", "false").lower() == "true"
   ```

2. **Manejo dual en `server.py`:**
   ```python
   try:
       # En producción estricta, validar certificados
       resp = requests.get(job.url, timeout=10, verify=PHISHGUARD_STRICT_TLS, ...)
   except requests.exceptions.SSLError as ssl_err:
       # Diferenciar host con certificado roto: registrar como indicio sospechoso en M1
       logger.warning("Fallo TLS en destino %s: %s", job.url, ssl_err)
       # Si strict está desactivado para compatibilidad con malware caídos, fallback con flag
   ```

3. **Migración de servicio de geolocalización a HTTPS:**
   Cambiar la conexión de `ip-api.com` a endpoint HTTPS seguro con contexto SSL por defecto:
   ```python
   conn = http.client.HTTPSConnection("ip-api.com", timeout=3, context=ssl.create_default_context())
   ```

---

## 4. Matriz de Aprobaciones y Roles

| Hito | Responsable Propuesto | Criterio de Aprobación | Estado Actual |
|---|---|---|---|
| **Exclusiones en `.gitignore`** | Auditor / Desarrollador | Reglas añadidas sin efectos adversos | **EJECUTADO** |
| **Generación de nueva clave de extensión** | Propietario del Repositorio | Par de claves RSA 2048-bit fuera de Git | PENDIENTE |
| **Desvinculación `git rm --cached`** | Propietario del Repositorio | Aprobación de nuevo commit en `corrections-phase2` | PENDIENTE |
| **Reescritura de historial `git-filter-repo`** | Propietario del Repositorio | Respaldo verificado + ventana de mantenimiento | PENDIENTE |
| **Hardening de TLS en backend (L12)** | Arquitecto de Software | Pruebas de no-regresión en suite de tests | PENDIENTE FASE POSTERIOR |
