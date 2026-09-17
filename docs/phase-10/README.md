# Fase 10 - Robustez adversarial controlada

El paquete `phishguard_robustness` genera perturbaciones locales y deterministas
para URL y HTML sintético: ruido de path, leetspeak, sustituciones ASCII,
espacios, orden de atributos y wrappers. No realiza solicitudes ni despliega
contenido.

`robustness_metrics` compara error limpio/perturbado, cambio medio de
probabilidad y tasa de cambio de etiqueta. Las perturbaciones se aplican después
de congelar el modelo y se evalúan en un conjunto separado; no se usan para
ajustar features o umbrales.
