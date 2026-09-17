from __future__ import annotations

import socket
import time
from typing import Protocol

from phishguard_infra.models import Resolution


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> Resolution: ...


class SocketResolver:
    """Resolve A/AAAA records through the system resolver without connecting."""

    def resolve(self, host: str, port: int) -> Resolution:
        started = time.perf_counter()
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = tuple(sorted({record[4][0] for record in records}))
        return Resolution(
            host=host,
            addresses=addresses,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
