# secretref documentation

A config file should be able to say *where* a secret lives without holding
the secret. That is the whole idea; everything here follows from it.

```json
{
  "database": {
    "host": "db.internal",
    "password": {"env": "DATABASE_PASSWORD"}
  }
}
```

```python
from secretref import load

config = load("config.json")
config.get("database.host")              # "db.internal"
config.secret("database.password").resolve()
```

## Start here

| Page | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Install, a first config, reading a value. Ten minutes. |
| [Reference forms](reference-forms.md) | `env`, `file`, `command`, `literal` — and which to reach for. |
| [Policies](policies.md) | Bounding what a config is allowed to reach. |
| [Auditing](auditing.md) | Finding secrets that ended up inline, in code and in CI. |
| [Extending](extending.md) | Changing a pattern, key name or marker without waiting for a release. |
| [Caching](caching.md) | When resolution is expensive enough to cache. |
| [Deployment](deployment.md) | Recipes for Docker, Kubernetes, systemd, serverless and a laptop. |
| [API reference](api.md) | Every public name, with signatures. |
| [Security](security.md) | What an attacker can do, and what this library does not protect. |
| [Performance](performance.md) | Measured costs, so you can choose a form knowingly. |
| [Limitations](limitations.md) | What it does not do, stated plainly. |
| [Comparison](comparison.md) | Against OmegaConf, Dynaconf and himl. |
| [Encryption](encryption.md) | Why this does no cryptography, and what to use instead. |

## The shape of it

```
load()  ──>  Config  ──>  SecretRef  ──>  resolve()
                 │                             │
                 │                             ├── a Policy decides whether
                 │                             │   this source is permitted
                 │                             └── a Resolver fetches it
                 │
                 └──>  audit()  ──>  [Finding]   (resolves nothing by default)
```

Four pieces, each with one job:

- **`Config`** holds parsed configuration and finds the references in it.
- **`SecretRef`** describes one secret's location. It is not the secret.
- **A policy** bounds what a reference may reach — one per form.
- **A resolver** fetches the value, once the policy has permitted it.

The separation is what lets `audit()` report on a config it refuses to
execute: it asks the policy and parses the reference without ever calling a
resolver.

## Design commitments

These do not change between versions:

1. **A value never appears in a message, a repr or a log line.** Errors name
   the reference, not the secret.
2. **Reading is explicit.** Nothing resolves at parse time or at import.
3. **Auditing has no side effects** unless you pass `resolve=True`.
4. **The strict default is the safe one.** Command references are off until
   you name the executables you trust.
