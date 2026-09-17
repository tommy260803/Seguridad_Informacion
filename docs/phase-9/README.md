# Fase 9 - Explicabilidad trazable

`phishguard_explain` transforma evidencia estructurada en razones ordenadas por
contribución absoluta. Cada razón conserva `evidence_id`, fuente, feature,
valor y contribución; los elementos no fiables no se presentan como motivos.

El motor solo redacta un resumen acotado y no modifica la decisión ni añade
hechos. Un LLM, si se incorpora posteriormente, recibiría únicamente este
registro y sus referencias, y su texto se trataría como presentación no
autoritativa.
