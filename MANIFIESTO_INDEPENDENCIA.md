# Manifiesto de Independencia Experimental y Auditoría de Cohorte Externa (N=240)

**Proyecto:** PhishPe / RAEA-Phish  
**Investigación:** Detección Automatizada de Sitios Web de Phishing Mediante Adquisición Adaptativa de Evidencia Basada en Riesgo y Disponibilidad  
**Fecha de Auditoría:** 2026-10-22  
**Norma de Auditoría:** Doble Ciego Metodológico, Prevención Estricta de Fuga de Datos (Data Leakage) y Trazabilidad Criptográfica  

---

## 1. Resumen Ejecutivo de la Auditoría

Se auditó de forma independiente la población externa de evaluación conformada por **240 observaciones** (120 de phishing activo y 120 legítimas benignas). La cohorte proviene de 6 fuentes de inteligencia independientes (40 observaciones por fuente).

### Resultados Clave de la Auditoría:
1. **Solapamiento Cero (0.0% Data Leakage):**
   - **Solapamiento de URLs con entrenamiento (176,201 muestras):** 0 observaciones (0.00%).
   - **Solapamiento de dominios registrados (PSL) con entrenamiento:** 0 dominios (0.00%).
   - **Solapamiento de URLs con partición de calibración ($N=300$):** 0 observaciones (0.00%).
   - **Solapamiento de dominios registrados con partición de calibración:** 0 dominios (0.00%).
   - **Solapamiento de dominios registrados con cohorte retrospectiva ($N=118$ / $N=600$):** 0 dominios (0.00%).
2. **Extracción Normalizada de Dominio Registrado:**
   - 100% de los 240 dominios registrados fueron extraídos y verificados contra la lista oficial de sufijos públicos (*Public Suffix List* - PSL).
   - 240 dominios registrados únicos en la muestra (sin duplicación interna de dominios).
3. **Distribución de Calidad de Etiquetas (5 Categorías Rigurosas):**
   - `VERIFICADA_DOCUMENTALMENTE`: **80 observaciones (33.33%)** (40 CISA .gov oficiales + 40 CERT Polska oficiales).
   - `RESPALDADA_POR_FUENTE_ESPECIALIZADA`: **107 observaciones (44.58%)** (40 Phishing Army + 40 HIPO Universities + 27 OpenPhish en dominio dedicado).
   - `RESPALDADA_CON_LIMITACIONES`: **53 observaciones (22.08%)** (40 Majestic Million head-2500 + 13 OpenPhish en plataformas compartidas/DNS dinámico).
   - `INCIERTA`: **0 observaciones (0.00%)**.
   - `NO_VERIFICABLE`: **0 observaciones (0.00%)**.
4. **Infraestructura Compartida y DNS Dinámico:**
   - Se identificaron **14 URLs (5.83%)** operando sobre plataformas multi-inquilino o DNS dinámico (`github.io`, `cprapid.com`, `ddnss.de`, `duckdns.org`, `home-webserver.de`, `blogspot.com`).

---

## 2. Composición y Trazabilidad de Feeds

| Fuente Primaria | Clase | N | Tipo de Evidencia | Archivo de Evidencia Cruda | Calidad de Etiqueta |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **CERT Polska** | Phishing (1) | 40 | Registro oficial de incidentes CSIRT nacional | `raw_feeds/cert_pl_domains.txt` | `VERIFICADA_DOCUMENTALMENTE` |
| **CISA DotGov** | Legítimo (0) | 40 | Registro oficial del gobierno federal de EE.UU. | `raw_feeds/cisa_dotgov.csv` | `VERIFICADA_DOCUMENTALMENTE` |
| **OpenPhish** | Phishing (1) | 40 | Feed operativo comercial de inteligencia de amenazas | `raw_feeds/openphish_feed.txt` | `RESPALDADA_POR_FUENTE_ESPECIALIZADA` / `RESPALDADA_CON_LIMITACIONES` |
| **Phishing Army** | Phishing (1) | 40 | Lista comunitaria especializada de bloqueo activo | `raw_feeds/phishing_army.txt` | `RESPALDADA_POR_FUENTE_ESPECIALIZADA` |
| **HIPO Universities** | Legítimo (0) | 40 | Directorio mundial de universidades acreditadas | `raw_feeds/hipo_universities.json` | `RESPALDADA_POR_FUENTE_ESPECIALIZADA` |
| **Majestic Million** | Legítimo (0) | 40 | Sitios web del top 2500 por volumen de tráfico | `raw_feeds/majestic_million_head2500.csv` | `RESPALDADA_CON_LIMITACIONES` |

---

## 3. Análisis Forense de Plataformas Compartidas y DNS Dinámico

De las 240 URLs, 14 muestras pertenecen a servicios de alojamiento gratuito, proveedores de DNS dinámico o plataformas multi-inquilino donde el control administrativo del dominio raíz no pertenece al creador de la URL:

1. **GitHub Pages (`github.io` - 4 casos):**
   - URLs: Repositorios de usuarios que clonaron interfaces de Netflix, Amazon, etc. o crearon páginas de phishing.
   - Evaluación: El dominio raíz pertenece a GitHub Inc., pero el prefijo de usuario y la ruta confirman el contenido fraudulento reportado por OpenPhish.
2. **cPanel Dynamic DNS (`cprapid.com` - 1 caso):**
   - URL: Servidor cPanel con subdominio dinámico basado en IP.
3. **DuckDNS (`duckdns.org` - 1 caso):**
   - Proveedor de DNS dinámico frecuentemente utilizado para evadir reputación estática de dominios.
4. **DDNSS y Home-Webserver (`ddnss.de`, `home-webserver.de` - 3 casos):**
   - Hosts dinámicos en Alemania utilizados en campañas de phishing activas.
5. **Blogger (`blogspot.com` - 2 casos):**
   - 1 caso de phishing activo (`facebooklogincc.blogspot.com`) y 1 legítimo de Majestic (`bp.blogspot.com`).

---

## 4. Trazabilidad Temporal e Inmutabilidad de Modelos

Para garantizar que la evaluación externa no incurra en sesgo retrospectivo de optimización (*p-hacking* o sobreajuste de hiperparámetros):

1. **Congelamiento de Modelos Base:**
   - Los clasificadores $M_0$ (léxico-heurístico), $M_1$ (LightGBM infraestructural) y $M_2$ (LightGBM de contenido HTML) fueron entrenados y congelados antes de la evaluación externa.
   - Sus pesos y transformadores no fueron reajustados sobre ninguna de las 240 observaciones externas.
2. **Congelamiento de Parámetros RAEA:**
   - La función de riesgo asimétrico utilizó $\gamma = 15.0$ (penalización severa por falso negativo), $C_{fp} = 1.0$, $C_{abst} = 0.35$ y $p_{safe} = 0.02$.
   - Ninguno de estos umbrales fue alterado para beneficiar artificialmente a RAEA en la cohorte externa.
3. **Origen de las Sondas de Red:**
   - Las sondas de red y contenido multimodales provienen del repositorio histórico de validación Fase 2 (`external_multimodal_probe_n240.jsonl`), lo que asegura que las latencias de red, respuestas HTTP y estados de disponibilidad reflejan condiciones de adquisición del mundo real observadas sin manipulación sintética.

---

## 5. Veredicto Final de Independencia

La cohorte externa de $N=240$ satisface los criterios más exigentes de validez externa e independencia experimental:
- Cero solapamiento léxico ni de dominio con conjuntos de entrenamiento o calibración.
- 100% de trazabilidad a fuentes primarias verificadas.
- Inmutabilidad estricta de políticas y parámetros algorítmicos.
