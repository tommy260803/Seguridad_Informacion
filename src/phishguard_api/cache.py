"""
Decision Cache for PhishGuard API.
Provides high-performance in-memory LRU caching with TTL expiration to eliminate
redundant inferences for frequently analyzed URLs and trusted benign domains.
"""

from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlparse

class DecisionCache:
    """Thread-safe in-memory LRU cache with TTL expiration."""

    def __init__(self, max_size: int = 10_000, default_ttl: int = 3600):
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip().lower()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached analysis if present and not expired."""
        key = self._normalize_url(url)
        now = time.time()

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            if now > entry["expires_at"]:
                del self._cache[key]
                self._misses += 1
                return None

            self._hits += 1
            # Move to end for LRU behavior
            self._cache[key] = entry
            return dict(entry["data"])

    def set(self, url: str, data: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Store an analysis decision in cache."""
        key = self._normalize_url(url)
        ttl = ttl if ttl is not None else self._default_ttl
        now = time.time()

        with self._lock:
            # Evict oldest entry if at capacity
            if len(self._cache) >= self._max_size and key not in self._cache:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]

            self._cache[key] = {
                "data": data,
                "cached_at": now,
                "expires_at": now + ttl
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate
            }

# Global singleton instance
decision_cache = DecisionCache()
