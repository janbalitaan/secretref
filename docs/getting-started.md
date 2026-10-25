# Getting started

## Install

```bash
pip install secretref          # or: uv add secretref
pip install 'secretref[yaml]'  # if your config is YAML
```

Python 3.10 or newer. No required dependencies.

## A first config

Put the shape of your configuration in a file, and the location of each
secret beside it:

```json
{
  "service_name": "billing",
  "database": {
    "host": "db.internal",
    "port": 5432,
    "password": {"env": "DATABASE_PASSWORD"}
  },
  "stripe": {
    "secret_key": {"env": "STRIPE_SECRET_KEY"}
  }
}
```

This file is safe to commit. It records that a database password exists and
where to look for it; it does not record the password.

## Reading it

```python
from secretref import load

config = load()                            # finds config.json in the cwd
config = load("config/production.json")    # or name it

config.get("database.host")                # "db.internal"
config.get("database.port")                # 5432
config.get("missing.key", "a fallback")    # "a fallback"
config.require("service_name")             # raises if absent
```

Plain values come back as they are. A secret needs one more step, so that
reading one is always visible in the code:

```python
password = config.secret("database.password").resolve()
```

`secret()` returns a `SecretRef` — a description of where the value lives.
`resolve()` is what goes and gets it.

## Seeing what a config expects

Before a deployment, the useful question is which variables need to be set:

```bash
$ secretref show
  database.password  env 'DATABASE_PASSWORD'
  stripe.secret_key  env 'STRIPE_SECRET_KEY'

2 references
```

This reads nothing. It lists what the config points at.

## Checking it

```bash
$ secretref audit
config.json: nothing to report
```

Add a secret inline and the audit says so:

```json
{"stripe": {"secret_key": "j4K9mQ2xR7vN8pL3wT6yB1zF5h"}}
```

```bash
$ secretref audit
error: stripe.secret_key: a literal secret inside a repository
  try: move it to an environment variable and reference it:
       {"env": "YOUR_VAR"} — and rotate it, since git history keeps
       the old value
```

Exit status is `1`, so this works as a CI check:

```yaml
- run: pip install secretref
- run: secretref audit --strict
```

## Wiring it into an application

One place that loads configuration, and the rest of the application takes
values from it:

```python
# settings.py
from dataclasses import dataclass
from secretref import load


@dataclass(frozen=True)
class Settings:
    database_url: str
    stripe_key: str

    @classmethod
    def from_config(cls, path: str | None = None) -> "Settings":
        config = load(path)
        password = config.secret("database.password").resolve()
        host = config.require("database.host")
        return cls(
            database_url=f"postgresql://app:{password}@{host}/billing",
            stripe_key=config.secret("stripe.secret_key").resolve(),
        )
```

Resolving at startup rather than per request means a missing secret fails the
deployment instead of the first request that needs it.

## Where next

- Secrets in files or a password manager: [reference forms](reference-forms.md)
- Bounding what a config may reach: [policies](policies.md)
- Deploying it: [deployment](deployment.md)
