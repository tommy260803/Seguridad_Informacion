# Fase 7 - Orquestación adaptativa

`phishguard_orchestrator` implementa una política explícita y determinista.
Comienza con URL, calcula incertidumbre por entropía y consulta infraestructura,
contenido y visual en ese orden mientras exista presupuesto. Cada transición
registra motivo, probabilidad, incertidumbre y presupuesto restante.

La salida es `phishing`, `legitimate` o `uncertain`; esta última se produce si
la evidencia no alcanza el umbral y no queda presupuesto o modalidad disponible.
Las probabilidades de las modalidades son entradas del motor: la política no
entrena ni inventa predicciones.

## Gate

- congelar umbrales y costes usando únicamente validation;
- comparar M3 fijo contra esta política sobre las mismas muestras;
- medir modalidades consultadas, latencia y coste acumulado antes de avanzar a
  abstención/calibración formal.
