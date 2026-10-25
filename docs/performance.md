# Performance

Measured, so you can pick a reference form knowing what it costs. Numbers
from a developer laptop; treat the ratios as the stable part.

## Cost per resolution

| Source | Cold | Cached |
| --- | --- | --- |
| `env` | **1.0 µs** | 0.3 µs |
| `file` | **12.4 µs** | 0.3 µs |
| `literal` | ~0.2 µs | n/a |
| `command` (`echo`) | **937 µs** | 0.3 µs |
| `command` (a real secrets CLI) | **tens to hundreds of ms** | 0.3 µs |

The shape of it: `env` and `file` are cheap enough to ignore. A `command` is
a thousand times more expensive before the tool has done anything, because it
is a process spawn — and a cloud secret store adds a network round trip on
top.

**If you use command references, enable caching.** It is the one case where
the default costs real time.

```python
from secretref import ResolutionCache

ResolutionCache().enable(ttl_seconds=300)
```

## Cost of loading and auditing

For a 50-service config, roughly 9 KB:

| Operation | Time |
| --- | --- |
| `load()` | 0.04 ms |
| `config.get("a.b.c")` | 0.001 ms |
| `config.secrets()` | 0.31 ms |
| `audit()` | 2.4 ms |

Scaling is linear in the size of the config:

| Services | Bytes | `load()` | `secrets()` | `audit()` |
| --- | --- | --- | --- | --- |
| 10 | 710 | 0.05 ms | 0.07 ms | 0.23 ms |
| 100 | 7 KB | 0.06 ms | 0.23 ms | 0.78 ms |
| 1 000 | 77 KB | 0.36 ms | 2.20 ms | 7.07 ms |
| 5 000 | 397 KB | 1.78 ms | 11.26 ms | 33.04 ms |

Nothing here is a hot path: `load` and `audit` run once at startup or once in
CI. A 5 000-service config is not a thing, and it would audit in 33 ms if it
were.

## Startup cost

```
import secretref        17 ms
secretref policy        30 ms   (most of which is Python itself starting)
```

Mostly `dataclasses` pulling in `inspect`, plus compiling the detection
patterns. Both are paid once.

## What is worth optimizing

Measured rather than assumed, and the answer is mostly nothing:

- **Resolution** — microseconds for `env` and `file`. A command is expensive;
  the cache answers it.
- **Loading and auditing** — milliseconds, linear, run once.
- **Import** — 17 ms, paid once.

The one real decision is caching command references, and the one real
constraint is that caching holds plaintext secrets in process memory. See
[caching](caching.md) for when that trade is worth making.

## Reproducing these

The benchmarks are not in the test suite — they measure a machine, not
behavior, and a timing assertion in CI is a flaky test. To re-measure:

```python
import time
from secretref import SecretRef

reference = SecretRef.parse({"env": "PATH"})
reference.resolve()                       # warm the import

start = time.perf_counter()
for _ in range(10_000):
    reference.resolve()
print((time.perf_counter() - start) / 10_000 * 1e6, "µs")
```
