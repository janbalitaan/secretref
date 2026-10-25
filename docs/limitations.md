# Limitations

Stated plainly, because a security tool that overstates itself is worse than
one that does less. Each of these is a reasonable thing to send a pull
request about.

## The audit cannot find a secret it does not recognize as one

Two checks run over plain values.

**By value.** A credential matching a format its issuer publishes — an AWS
access key ID, a GitHub or Stripe token, a private key block, a connection
string with a password — is reported whatever the key is called, and named so
you know what to rotate.

**By key name.** A value under a key like `password` or `api_key` is reported
even when its shape says nothing. The only way to catch an internal
credential with no published format.

**What neither finds:** a secret with no recognizable shape under a key with
no recognizable name. A password split across two fields. One base64-encoded,
or assembled at runtime. A credential for a provider whose format is not in
the list.

The list is `KNOWN_SECRET_FORMATS` in `patterns.py`. Adding one is a line
there and a case in `tests/detection/`.

This is a check against carelessness, not against determination. For scanning
a repository's *history*, `gitleaks` and `detect-secrets` do that properly.

## It does not encrypt anything

A resolved secret is plaintext in process memory, like any other string.
Python offers no way to pin or wipe one reliably, and claiming otherwise
would be the kind of false comfort that gets a tool trusted too far.

If a secret must not be readable by whatever can read your process, it needs
a different mechanism — an HSM, an enclave, or a service that holds the key
and performs the operation for you.

## Repository detection is a heuristic

The audit walks up from the config looking for `.git`, which decides whether
a literal secret is an error or a warning. A shallow checkout, an exported
tree, a submodule or a worktree can read differently from what you expect.

`--strict` removes the question: warnings block too.

## It is not a schema library

There is no type checking, no required-field validation, no coercion. A port
that should be an integer and is a string stays a string.

Use pydantic, attrs or a dataclass for that, and let this answer where the
secrets are:

```python
Settings(
    host=config.require("database.host"),
    port=int(config.require("database.port")),
    password=config.secret("database.password").resolve(),
)
```

## It does not merge or interpolate

No hierarchical merging, no layered environments, no `${VAR}` substitution
inside values. One file, read as it is.

If you need those, use OmegaConf, Dynaconf or himl and audit the result — see
[comparison](comparison.md).

## `required: false` is quiet by design

An optional reference that resolves to nothing returns an empty string. If
the difference between "set to empty" and "not set" matters to you, this does
not express it.

A policy refusal is **not** quiet: it raises whether or not the reference is
optional, because a forbidden reference is a configuration mistake rather
than an absent secret.

## Environment references are open by default

Any variable may be read. A process's environment is already readable by that
process, so this is not an escalation — but it matters when a config is
rendered into output a user sees, where a reference becomes a way of asking
for a variable nobody meant to expose.

`EnvironmentPolicy().restrict(...)` narrows it. It is not the default because
it would break the deployments that need no policy at all.

## Caching has no invalidation

Entries expire on their TTL or on `clear()`. Nothing watches for a rotated
secret, and nothing coordinates between processes. A TTL is how long a
rotated secret keeps working after it should have stopped.

## Command references depend on a CLI

Reading from Vault, 1Password or AWS Secrets Manager means shelling out to
their command-line tool: a dependency to install, a subprocess per
resolution, and a program whose output format may change. A native client
library is better if one exists and you are happy to depend on it.

## Only JSON and YAML

TOML and INI are not supported. JSON needs nothing; YAML needs the `yaml`
extra. A parser is a small class in `parsers/` if you want to add one.

## Policies are process-wide

Each is a singleton, which is what stops a library deeper in your stack
widening a policy by constructing its own. The cost is that two parts of one
process cannot have different policies. If you need that, the boundary is a
process, not an object.
