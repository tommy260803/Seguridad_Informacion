# Fase 6 - Fusión multimodal fija

`phishm3` entrena un benchmark que siempre recibe las cuatro familias de
evidencia: URL, infraestructura, contenido HTML y señales visuales. Reutiliza
los splits, calibración y selección de candidatos de M2 para que la comparación
sea atribuible a la nueva modalidad.

El registro identifica las versiones `url-features-1.0.0`,
`infra-features-1.0.0`, `content-features-1.0.0` y `visual-features-1.0.0`.
La ejecución no navega ni captura URLs por sí sola: consume únicamente
`results.jsonl` previamente producidos por componentes controlados.

## Gate

- comparar M0, M1, M2 y M3 sobre el mismo protocolo sin usar `test` para ajustar
  umbrales;
- registrar latencia, cobertura de artefactos y fallos por modalidad;
- congelar el benchmark antes de implementar la adquisición adaptativa de Fase 7.
