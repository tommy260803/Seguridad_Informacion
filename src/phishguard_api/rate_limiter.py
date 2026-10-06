from __future__ import annotations

import os
import time
from collections import defaultdict
import asyncio
from fastapi import Request, HTTPException

# Configuración de límite por minuto por IP (por defecto 120 req/min)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
WINDOW_SECONDS = 60.0

class InMemoryRateLimiter:
    """
    Limitador de velocidad de ventana deslizante en memoria para proteger
    los endpoints de la API contra ataques DoS y fuerza bruta.
    """
    def __init__(self, limit: int = RATE_LIMIT_PER_MINUTE, window: float = WINDOW_SECONDS):
        self.limit = limit
        self.window = window
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.time()

    async def check(self, client_id: str) -> None:
        async with self._lock:
            now = time.time()
            # Limpieza periódica cada 120s para prevenir fugas de memoria
            if now - self._last_cleanup > 120.0:
                self._cleanup(now)
                self._last_cleanup = now

            timestamps = self._requests[client_id]
            # Filtrar marcas de tiempo fuera de la ventana
            cutoff = now - self.window
            self._requests[client_id] = [ts for ts in timestamps if ts > cutoff]

            if len(self._requests[client_id]) >= self.limit:
                retry_after = int(self.window - (now - self._requests[client_id][0]))
                retry_after = max(1, retry_after)
                raise HTTPException(
                    status_code=429,
                    detail=f"Límite de peticiones excedido ({self.limit} req/min). Reintente en {retry_after}s.",
                    headers={"Retry-After": str(retry_after)}
                )

            self._requests[client_id].append(now)

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window
        stale_clients = [
            cid for cid, timestamps in self._requests.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for cid in stale_clients:
            del self._requests[cid]

# Instancia global del limitador
limiter = InMemoryRateLimiter()

async def rate_limit_dependency(request: Request) -> None:
    """Dependencia inyectable de FastAPI para control de flujo."""
    # Extraer IP real detrás de proxys o socket directo
    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else "unknown"

    await limiter.check(client_ip)
