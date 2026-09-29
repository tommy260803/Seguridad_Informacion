from __future__ import annotations

import socket
import time
from typing import Protocol

from phishguard_infra.models import Resolution


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> Resolution: ...


import atexit
import concurrent.futures

_SHARED_RESOLVER_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="dns-resolver"
)
atexit.register(lambda: _SHARED_RESOLVER_EXECUTOR.shutdown(wait=False))

class SocketResolver:
    """Resolve A/AAAA records through the system resolver with a strict bounded timeout and shared thread pool."""

    def __init__(self, timeout: float = 2.5, executor: concurrent.futures.ThreadPoolExecutor | None = None) -> None:
        self.timeout = timeout
        self._executor = executor or _SHARED_RESOLVER_EXECUTOR

    def resolve(self, host: str, port: int) -> Resolution:
        started = time.perf_counter()
        addresses: tuple[str, ...] = ()
        try:
            future = self._executor.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
            records = future.result(timeout=self.timeout)
            addresses = tuple(sorted({record[4][0] for record in records}))
        except (concurrent.futures.TimeoutError, socket.gaierror, socket.timeout, OSError):
            # Safe fallback on DNS timeout or resolution error
            addresses = ()
        except Exception:
            addresses = ()

        return Resolution(
            host=host,
            addresses=addresses,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
