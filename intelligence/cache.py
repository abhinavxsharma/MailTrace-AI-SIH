"""
MAILTRACE AI — In-memory TTL cache for threat intelligence lookups.

Provides thread-safe, time-bounded in-memory caching to avoid redundant
network lookups during analysis. No disk writes or database persistence.
"""

from __future__ import annotations

import threading
import time
from typing import Generic, TypeVar

T = TypeVar("T")


class InMemoryTtlCache(Generic[T]):
    """
    Thread-safe in-memory cache with time-to-live (TTL) expiration.

    Attributes:
        ttl_seconds: Cache entry lifetime in seconds (default 300s = 5m).
        max_size: Maximum entries before pruning (default 1000).
    """

    def __init__(self, ttl_seconds: int = 300, max_size: int = 1000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: dict[str, tuple[float, T]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> T | None:
        """Retrieve a cached value if present and not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expiry, value = entry
            if time.time() > expiry:
                del self._cache[key]
                return None
            return value

    def set(self, key: str, value: T, ttl_seconds: int | None = None) -> None:
        """Store a value in cache with expiration."""
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        expiry = time.time() + ttl
        with self._lock:
            # Simple eviction if capacity reached
            if len(self._cache) >= self.max_size:
                self._prune_expired()
                if len(self._cache) >= self.max_size:
                    # Remove the oldest item
                    oldest_key = next(iter(self._cache))
                    del self._cache[oldest_key]
            self._cache[key] = (expiry, value)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()

    def _prune_expired(self) -> None:
        """Remove expired entries (internal, caller must hold lock)."""
        now = time.time()
        expired_keys = [k for k, (exp, _) in self._cache.items() if now > exp]
        for k in expired_keys:
            del self._cache[k]
