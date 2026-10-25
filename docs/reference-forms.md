# Reference forms

Four ways to say where a secret lives. Any of them can appear wherever a
value would.

| Form | Reads from | Side effects | Default policy |
| --- | --- | --- | --- |
| `{"env": "NAME"}` | an environment variable | none | any variable |
| `{"file": "/path"}` | a file's contents | none | the secret mounts only |
| `{"command": "tool arg"}` | a command's stdout | **runs a program** | off |
| `{"literal": "value"}` | the config itself | none | always reported |

## `env` — an environment variable

```json
{"password": {"env": "DATABASE_PASSWORD"}}
```

The default for most deployments. Every platform can inject an environment
variable, so this needs no setup at all.

```python
config.secret("password").resolve()   # os.environ["DATABASE_PASSWORD"]
```

An unset variable resolves to empty, which `required` and `default` then
decide the meaning of. Trailing whitespace is stripped, because a secret
pasted into a dashboard field often carries a newline.

## `file` — a mounted secret

```json
{"password": {"file": "/run/secrets/db-password"}}
```

How Docker Swarm, Kubernetes and systemd deliver secrets, and better than an
environment variable in one specific way: a child process does not inherit
it, and it does not appear in `/proc/<pid>/environ`.

By default only `/run/secrets` and `/run/credentials` may be read — see
[policies](policies.md) to widen that for a laptop.

```python
FilePolicy().restrict("/etc/myapp/secrets")
```

## `command` — a password manager or secret store

```json
{"password": {"command": "op read op://production/database/password"}}
```

For a secrets manager that ships a CLI before it ships a Python client.
**Off by default**, because a config that can name a command can name any
command:

```python
from secretref import CommandPolicy

CommandPolicy().allow("op")    # just the 1Password CLI
```

The command is split with `shlex` and run without a shell, so a locator
cannot smuggle in a pipeline, a redirect or a second command. It runs with
only the environment variables the policy names, a timeout, and a cap on how
much output it may produce.

This is the only form with side effects, which is why `audit()` reports one
as *not verified* rather than running it.

```python
reference.has_side_effects()   # True only for a command
```

## `literal` — a value that is already here

```json
{"password": {"literal": "development-only"}}
```

Explicit about what it is, which is the point: `audit()` reports every
literal, so a value declared this way is visible rather than hidden among
the plain configuration.

```python
reference.resolve(allow_literal=False)   # raises instead
```

Use it for a development placeholder or a test fixture. A plain string in a
config is also treated as a literal when it looks like a secret.

## Optional and defaulted references

```json
{
  "smtp_password": {"env": "SMTP_PASSWORD", "required": false},
  "region": {"env": "AWS_REGION", "default": "us-east-1"}
}
```

- **`required: false`** — an unset variable resolves to empty rather than
  raising. For a feature that is off when unconfigured.
- **`default`** — a value to fall back to. For a setting with a sensible
  value, not for a secret.

A default does not override a policy refusal. A forbidden reference raises
whether or not it has a default, because a policy refusal is a configuration
mistake and silently falling back would hide it.

## Choosing between them

- **Everything is an environment variable** → use `env`, set no policy.
- **Kubernetes or Docker secrets** → use `file`, set no policy.
- **A password manager** → use `command`, allow the one CLI.
- **A development placeholder** → use `literal`, and let the audit remind you.

Mixing forms in one config is normal: the same file can read a database
password from the environment and a signing key from a mounted file.

## Building one in code

```python
from secretref import SecretRef

SecretRef.parse({"env": "DATABASE_PASSWORD"})
SecretRef.parse({"file": "/run/secrets/key"})
SecretRef.parse("an-inline-value")            # a literal
```

`parse` accepts exactly what appears in a config file, so a reference built
in a test behaves identically to one loaded from disk.
