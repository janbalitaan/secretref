# Caching

Off by default. Resolution is lazy — a value is fetched when you ask for it,
every time you ask:

```python
reference = config.secret("database.password")
reference.resolve()   # fetches
reference.resolve()   # fetches again
```

For an environment variable that is a dictionary lookup, about a microsecond,
and caching it would be pointless. For a command it is a process spawn, and
for a cloud secret store a network round trip.

## When to enable it

```python
from secretref import ResolutionCache

ResolutionCache().enable(ttl_seconds=300)
```

**Enable it when you use `command` references and resolve more than once.**
That is the whole rule. Measured, a command costs about a millisecond at
best and tens to hundreds of milliseconds through a real secrets CLI, against
0.3 µs from the cache.

**Leave it off when** you resolve everything once at startup, or every
reference is `env` or `file`. There is nothing to win, and a cache holds
plaintext secrets in process memory for as long as its TTL.

## What it does

```python
cache = ResolutionCache()
cache.enable(ttl_seconds=300)
cache.enabled      # True
cache.stats()      # {"hits": 12, "misses": 3, "entries": 3, ...}
cache.hits
cache.misses
cache.clear()      # drop everything now
cache.disable()    # and stop caching
```

Keyed on the source and the locator together, so `{"env": "A"}` and
`{"file": "A"}` are different entries. Process-local: nothing is written to
disk, and nothing is shared between processes.

## Choosing a TTL

The TTL is how long a rotated secret keeps working after it should have
stopped.

| TTL | Suits |
| --- | --- |
| 60 s | A secret that rotates often, or a short-lived process. |
| 300 s | A reasonable default for a long-running service. |
| 3600 s | A secret that effectively never rotates. |

There is no invalidation beyond expiry and `clear()`. If something in your
deployment knows a secret has rotated, call `clear()` from there.

## The trade

A cache keeps plaintext secrets in memory. They are already in memory while
you hold the resolved value, so the difference is duration: a cache holds
them for the TTL whether or not anything is using them, which widens what a
memory dump or a core file would contain.

For most services that is a reasonable trade against a subprocess per
request. For a process that resolves one secret at startup it is pure
downside, which is why it is off by default.

## Not a secrets manager

This is a performance cache. It does not refresh, renew a lease, or
coordinate between instances. If you need leased credentials that rotate,
the secret store's own client does that properly — and `command` references
can call its CLI in the meantime.
