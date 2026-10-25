"""One shared store of already-resolved values.

A thin wrapper over `utils.TtlStore`, which holds the mechanics. What is left
here is the part that is actually about secrets:

    the key is (source, locator), so an env var and a file path that happen
    to share a name do not collide

    an empty resolution is never stored, because caching "this resolved to
    nothing" would hide a secret that appears later — the opposite of helpful
    during a deployment

    it is a singleton, because two references to the same variable should not
    each spawn their own subprocess, and a per-reference cache caches nothing

That last point is the only place in this library where a singleton is the
right answer, and the contrast is the useful part. `Tree`, `Repository` and
the parsers are classmethods on classes nobody constructs — stronger than a
singleton, since there is no instance to mutate. `Config`, `SecretRef` and
`Finding` must not be singletons at all, because more than one is the normal
case. Here the shared state *is* the feature.

Off by default, because caching changes two things a caller should decide:

    a secret stays in memory after the only read that needed it

    a rotated secret keeps serving the old value until the entry expires,
    which is the usual reason to set a ttl rather than leave it unbounded
"""

from __future__ import annotations

from threading import Lock
from typing import ClassVar

from secretref.utils.ttl_store import TtlStore


class ResolutionCache:
    """A process-wide store of resolved secrets, keyed by reference."""

    _instance: ClassVar[ResolutionCache | None] = None
    _singleton_lock: ClassVar[Lock] = Lock()

    def __new__(cls) -> ResolutionCache:
        """Return the one instance, creating it on first use.

        Double-checked under a lock, because two threads resolving at startup
        would otherwise each build a store and one would win — leaving the
        other thread's writes in an object nothing else can see.
        """
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialize()
                    cls._instance = instance
        return cls._instance

    def _initialize(self) -> None:
        """Set up the store. Called once, by __new__."""
        self._store: TtlStore[tuple[str, str], str] = TtlStore()
        self._enabled = False

    # -- configuration -----------------------------------------------------

    def enable(self, ttl_seconds: float | None = None) -> None:
        """Start caching, optionally expiring entries after `ttl_seconds`.

        A ttl is how a long-running process picks up a rotated secret without
        restarting. Without one an entry lives until the cache is cleared,
        which suits a short-lived process and not much else.
        """
        self._enabled = True
        self._store.ttl = ttl_seconds

    def disable(self) -> None:
        """Stop caching and drop everything held."""
        self._enabled = False
        self._store.clear()

    def clear(self) -> None:
        """Drop everything held, without changing whether caching is on.

        What to call after rotating a secret, and what a test fixture calls
        so one test cannot see another's values.
        """
        self._store.clear()

    @property
    def enabled(self) -> bool:
        """Whether resolved values are being kept."""
        return self._enabled

    # -- use ---------------------------------------------------------------

    def get(self, source: str, locator: str) -> str | None:
        """Return a cached value for this reference, or None.

        None means "resolve it" rather than "it resolved to nothing" — an
        empty resolution is never stored, so the two cannot be confused.
        """
        if not self._enabled:
            return None
        return self._store.get((source, locator))

    def put(self, source: str, locator: str, value: str) -> None:
        """Store a resolved value.

        An empty value is not stored. Caching "this resolved to nothing"
        would make a secret that appears later invisible until the cache is
        cleared, which is the opposite of helpful during a deployment.
        """
        if not self._enabled or not value:
            return
        self._store.put((source, locator), value)

    @property
    def hits(self) -> int:
        """Lookups served from the store."""
        return self._store.hits

    @property
    def misses(self) -> int:
        """Lookups that had to resolve."""
        return self._store.misses

    def stats(self) -> dict[str, int | bool | float | None]:
        """Counters for logging. Contains no values and no locators."""
        return {"enabled": self._enabled, **self._store.counters()}
