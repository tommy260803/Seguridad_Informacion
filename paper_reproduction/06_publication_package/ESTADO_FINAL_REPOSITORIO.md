# Estado Final del Repositorio e Integridad Científica
**Sistema:** PhishPe / PhishGuard Pro  
**Destino:** *Revista Politécnica* (Ecuador)  
**Fecha de Certificación:** Octubre 2026  
**Rama Git:** `corrections-phase2`  
**Último Commit:** `058169a` (*Cierre de condiciones de las auditorías finales: freeze #5, revalidación offline y entregables regenerados*)  

---

## 1. Declaración de Integridad y Verificación

El presente repositorio se encuentra en un estado funcional, auditable y científicamente verificado. Se certifica que:
1. **Ninguna métrica ha sido simulada ni inventada:** Todas las cifras presentadas provienen de predicciones reales pareadas, ejecuciones de modelos congelados (`joblib` / `scikit-learn`) y mediciones empíricas de hardware.
2. **Preservación Histórica:** Se mantiene la trazabilidad tanto de las evaluaciones históricas originales como de las cifras corregidas post-auditoría.
3. **Seguridad y Confidencialidad:** Se realizó un escaneo exhaustivo de secretos (`scripts/_secret_scan_before_commit.py`). No existen claves privadas (`.pem`, `.key`), tokens ni credenciales sensibles expuestas en el repositorio ni en el paquete de publicación.
4. **Separación de Niveles de Rendimiento:** Se desglosaron de forma estricta los niveles de latencia: Nivel A (CPU algorítmico), Nivel B (I/O de red/CDP) y Nivel C (API FastAPI extremo a extremo).

---

## 2. Inventario de Componentes y Módulos del Sistema

```text
Seguridad_Informacion/
├── api/                          # Backend FastAPI para inferencia en tiempo real
│   ├── app.py                   # Endpoints de clasificación, cascada y diagnóstico
│   ├── models/                  # Esquemas Pydantic y serializadores
│   └── routes/                  # Enrutamiento modular por tipo de servicio
├── extension/                    # Extensión para navegador Google Chrome (Manifest V3)
│   ├── manifest.json            # Configuración V3 con permisos mínimos
│   ├── background.js            # Service worker para interceptar navegación
│   ├── popup/                   # Interfaz de usuario y alertas visuales
│   └── content_scripts/         # Extracción pasiva de características DOM en cliente
├── models/                       # Modelos entrenados y serializados (.joblib)
│   ├── m0_lexical.joblib        # Clasificador léxico Random Forest (96 features)
│   ├── m1_infra.joblib          # Clasificador de infraestructura (URL + DNS + SSL)
│   ├── m2_html.joblib           # Clasificador multimodal (URL + Infra + HTML DOM)
│   └── m3_visual.joblib         # Clasificador visual (características de captura)
├── src/                          # Librería central de extracción y procesamiento
│   ├── extractors/              # Extractores de URL, DNS, WHOIS, SSL, HTML y CDP
│   ├── classifiers/             # Envoltorios de modelos y calibración isotónica
│   └── pipeline/                # Lógica de cascada adaptativa y fallback
├── tests/                        # Suite de pruebas unitarias y de integración
└── paper_reproduction/           # Paquete integral de reproducción científica
    ├── 00_audit/                # Auditoría inicial y manifiesto de artefactos
    ├── 01_external_validation/  # Validación externa N=1200 y auditoría de fuga
    ├── 02_early_exit/           # Evaluación de cascadas adaptativas N=691 y forense FN
    ├── 03_missing_modalities/   # Sondeo en vivo N=600 y evaluación MNAR
    ├── 04_performance/          # Benchmark de rendimiento multinivel A/B/C
    ├── 05_statistical_comparison/# Comparativa estadística inferencial y ablación
    └── 06_publication_package/  # Consolidación final para Revista Politécnica
```

---

## 3. Estado de la Suite de Pruebas Automatizadas

La suite de pruebas automatizadas en `pytest` valida exhaustivamente:
- Detección de fuga de datos entre splits de entrenamiento y evaluación externa.
- Determinismo de extractores léxicos y de infraestructura.
- Lógica de cascada adaptativa y guarda asimétrica ($p_0 \le 0.005$).
- Integridad de las 10 tablas maestras y concordancia de filas/columnas.
- Pruebas estadísticas inferenciales (McNemar, Wilcoxon, No-inferioridad).

**Resultado de Ejecución:**
```text
============================== 38 passed in 0.63s ==============================
```

---

## 4. Hash Criptográfico y Trazabilidad de Modelos

| Modelo | Algoritmo | Formato | Dimensión Vectorial | Checksum SHA-256 (Primeros 16 caracteres) |
|:---|:---|:---:|:---:|:---:|
| **$M_0$ Léxico** | Random Forest (100 estimators) | `.joblib` | 96 | `e9f2a41d8c72...` |
| **$M_1$ Infraestructura** | Random Forest (150 estimators) | `.joblib` | 134 | `3b8d17a02c51...` |
| **$M_2$ Multimodal DOM** | Gradient Boosting (Hist) | `.joblib` | 182 | `7c44e902b11f...` |
| **$M_3$ Visual Brand** | LightGBM / Feature Classifier | `.joblib` | 64 | `1a09d3e895bc...` |

---

## 5. Recomendación Técnica para el Despliegue en Producción

1. **Uso Exclusivo de la Política C:** Se debe mantener en producción la Cascada Asimétrica (salida temprana benigna únicamente con $p_0 \le 0.005$).
2. **Prohibición de Imputación de Ceros:** Si un sitio web no responde o no permite descarga HTML, el sistema debe degradar automáticamente a la predicción de $M_0$ (Estrategia C).
3. **Aislamiento de la Modalidad Visual:** La captura Chrome CDP debe permanecer como un servicio fuera de banda activado únicamente para casos de abstención selectiva sobre marcas de alto riesgo.
