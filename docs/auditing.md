# Auditing

An audit answers one question: **is this config holding a secret it should
only be pointing at?**

```python
from secretref import audit, load

for finding in audit(load("config.json")):
    print(finding)
```

```
error: payments.api_key: a Stripe secret key inside a repository, so git history keeps it
  try: rotate this credential, then reference it instead of storing it: {"env": "YOUR_VAR"}
```

## It resolves nothing

This is the most important thing about `audit()`. By default it resolves no
reference that has side effects:

```python
audit(config)                 # checks policy and shape; runs nothing
audit(config, resolve=True)   # also verifies each secret resolves
```

Auditing a config you did not write is the main use — a CI check on a pull
request — and a `command` reference that resolved would run whatever the pull
request contained. An earlier version did exactly that. Now a command
reference is reported as `not verified`, and `resolve=True` is how you opt in
for a config of your own.

## What it finds

| Finding | Severity | Why |
| --- | --- | --- |
| A credential matching a published format | error | It is live. Rotate it. |
| A literal secret inside a git repository | error | History keeps it after you delete it. |
| A literal secret in a config file | warning | Careless, but contained. |
| A reference the policy forbids | error | A configuration mistake. |
| A malformed reference | error | It will never resolve. |
| A value that looks like a placeholder | note | Probably fine, worth a look. |
| A reference that resolves to nothing | note | Often just a variable not set yet. |

Two independent checks run over plain values:

**By value.** A credential matching a shape its issuer publishes is reported
whatever the key is called. Nothing about `tracking.ref` suggests a
credential, which is exactly why the key name cannot be the only check.

**By key name.** A value under `password`, `api_key` or `token` is reported
even when its shape says nothing — the only way to catch an internal
credential with no published format.

## Severity, and what blocks

```python
from secretref import Severity

finding.blocking                       # True for an error
Severity.worst(f.severity for f in findings)
sorted(findings, key=lambda f: f.severity)   # most severe first
```

A literal secret is an **error** inside a repository and a **warning**
outside one. The difference is git: once a secret is committed, deleting it
does not remove it, so the remedy changes from "move it" to "move it and
rotate it".

## From the command line

```bash
secretref audit                    # find config.json and check it
secretref audit config/prod.json   # or name one
secretref audit --strict           # warnings block too
secretref audit --json             # machine-readable
```

| exit | means |
| --- | --- |
| `0` | nothing blocking |
| `1` | a blocking finding |
| `2` | could not run — no config, bad arguments, unparseable file |

The last two are separate so a pipeline can tell "your config has a problem"
from "this tool was used wrongly".

## In CI

```yaml
# .github/workflows/ci.yml
name: ci
on: [push, pull_request]

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install secretref
      - run: secretref audit --strict
```

`--strict` makes a literal secret fail the build whether or not the audit
found a repository above it. Worth having: the audit's repository detection
walks up looking for `.git`, which a shallow or exported checkout may not
have.

For several configs:

```yaml
      - run: |
          for config in config/*.json; do
            secretref audit --strict "$config"
          done
```

## As a startup check

In an application, the useful moment is startup — before serving a request
that would fail:

```python
from secretref import audit, load


def load_checked(path: str):
    """Load a config, refusing to start on anything blocking."""
    config = load(path)
    # resolve=True because this config is ours, and a secret that cannot be
    # fetched should stop the deployment rather than the first request.
    blocking = [f for f in audit(config, resolve=True) if f.blocking]
    if blocking:
        raise SystemExit("\n".join(str(f) for f in blocking))
    return config
```

## Machine-readable output

```python
finding.as_dict()
```

```json
{
  "severity": "error",
  "path": "payments.api_key",
  "message": "a Stripe secret key inside a repository, so git history keeps it",
  "remedy": "rotate this credential, then reference it instead of storing it: {\"env\": \"YOUR_VAR\"}",
  "blocking": true
}
```

No finding ever carries a value. These go into build logs.

## Auditing a config another library owns

The audit parses JSON or YAML and walks it. It does not care what reads the
file afterwards, so it works on a settings file belonging to Dynaconf,
OmegaConf, Hydra or anything else:

```bash
secretref audit settings.yaml          # a Dynaconf settings file
secretref audit conf/config.yaml       # a Hydra config
```

Another tool's interpolation syntax — `@format {env[X]}`, `${VAR}`,
`{{ssm.path(...)}}`, `%(name)s` — is recognized as a reference rather than
reported as a hardcoded secret.
