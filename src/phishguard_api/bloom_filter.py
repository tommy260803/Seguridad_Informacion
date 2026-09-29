"""
High-Speed In-Memory Bloom Filter for PhishGuard.
Provides O(1) membership testing for high-reputation trusted domains and known threat feeds,
enabling sub-millisecond bypass or pre-filtering before invoking ML models.
"""

from __future__ import annotations

import math
import hashlib
from typing import Iterable, Optional
from urllib.parse import urlparse

class BloomFilter:
    """Probabilistic data structure for O(1) set membership testing."""

    def __init__(self, expected_elements: int = 50_000, false_positive_rate: float = 0.001):
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate

        # Calculate optimal size (m) and hash functions count (k)
        self.size = int(- (expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        self.num_hashes = int((self.size / expected_elements) * math.log(2))
        self.bit_array = bytearray((self.size + 7) // 8)
        self._count = 0

    def _hashes(self, item: str) -> Iterable[int]:
        item_bytes = item.strip().lower().encode("utf-8")
        h1 = int(hashlib.sha256(item_bytes).hexdigest(), 16)
        h2 = int(hashlib.md5(item_bytes).hexdigest(), 16)
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, item: str) -> None:
        """Add an item to the Bloom filter."""
        for bit_index in self._hashes(item):
            byte_idx = bit_index // 8
            bit_idx = bit_index % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """Check if an item is likely in the set (zero false negatives)."""
        for bit_index in self._hashes(item):
            byte_idx = bit_index // 8
            bit_idx = bit_index % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def count(self) -> int:
        return self._count


# Top popular legitimate domains (Tranco Top-100 sample) pre-populated for fast-path evaluation
DEFAULT_TRUSTED_DOMAINS = (
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "wikipedia.org", "en.wikipedia.org", "es.wikipedia.org",
    "github.com", "www.github.com",
    "cloudflare.com", "www.cloudflare.com",
    "mozilla.org", "www.mozilla.org",
    "netflix.com", "www.netflix.com",
    "linkedin.com", "www.linkedin.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "x.com",
    "zoom.us", "slack.com",
    "stackoverflow.com", "reddit.com"
)


class DomainFilterManager:
    """Manages trusted whitelist and blacklist bloom filters."""

    def __init__(self):
        self.trusted_filter = BloomFilter(expected_elements=100_000, false_positive_rate=0.0005)
        self.threat_filter = BloomFilter(expected_elements=100_000, false_positive_rate=0.0005)
        for domain in DEFAULT_TRUSTED_DOMAINS:
            self.trusted_filter.add(domain)

    @staticmethod
    def extract_host(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            return urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            return ""

    def is_trusted(self, url: str) -> bool:
        host = self.extract_host(url)
        return bool(host and host in self.trusted_filter)

    def is_known_threat(self, url: str) -> bool:
        host = self.extract_host(url)
        return bool(host and host in self.threat_filter)


# Global singleton instance
domain_filter = DomainFilterManager()
