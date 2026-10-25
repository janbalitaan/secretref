"""A key-value store that forgets."""

from __future__ import annotations

from threading import Lock
import time
from typing import Generic, TypeVar

Key = TypeVar("Key")
Value = TypeVar("Value")


class TtlStore(Generic[Key, Value]):
    """Values held for a while, behind a lock, with hit and miss counters.

    Knows nothing about secrets. A plain store: keys in, values out, entries
    dropped once they are older than the lifetime. The counters are here
    because a cache nobody can measure is a cache nobody can tune.

    Not a singleton. Whether one store is shared is the caller's decision,
    and `ResolutionCache` is the one that makes it.
    """

    def __init__(self, ttl_seconds: float | None = None) -> None:
        self._entries: dict[Key, tuple[Value, float]] = {}
        self._lock = Lock()
        self._ttl = ttl_seconds
        self.hits = 0
        self.misses = 0

    @property
    def ttl(self) -> float | None:
        """How long an entry lives, or None for forever."""
        return self._ttl

    @ttl.setter
    def ttl(self, seconds: float | None) -> None:
        """Change the lifetime. Existing entries are judged by the new one."""
        with self._lock:
            self._ttl = seconds

    def __len__(self) -> int:
        """How many entries are held, expired ones included."""
        return len(self._entries)

    def get(self, key: Key) -> Value | None:
        """Return the value for a key, or None when absent or expired.

        An expired entry is dropped on the way out rather than by a sweep.
        For a store holding a handful of secrets that is enough, and it
        avoids a background thread.
        """
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            value, stored_at = entry
            if self._expired(stored_at):
                del self._entries[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    def put(self, key: Key, value: Value) -> None:
        """Store a value under a key."""
        with self._lock:
            self._entries[key] = (value, time.monotonic())

    def clear(self) -> None:
        """Drop every entry."""
        with self._lock:
            self._entries.clear()

    def counters(self) -> dict[str, int | float | None]:
        """Hits, misses and size. Contains no keys and no values."""
        return {
            "entries": len(self._entries),
            "hits": self.hits,
            "misses": self.misses,
            "ttl_seconds": self._ttl,
        }

    def _expired(self, stored_at: float) -> bool:
        """Whether an entry stored at that moment has outlived the ttl."""
        return self._ttl is not None and (time.monotonic() - stored_at) > self._ttl
