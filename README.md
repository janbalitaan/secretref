# secretref

Config files that name their secrets instead of containing them.

[![PyPI](https://img.shields.io/pypi/v/secretref)](https://pypi.org/project/secretref/)
[![Python](https://img.shields.io/pypi/pyversions/secretref)](https://pypi.org/project/secretref/)
[![CI](https://github.com/janbalitaan/secretref/actions/workflows/ci.yml/badge.svg)](https://github.com/janbalitaan/secretref/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/secretref)](https://github.com/janbalitaan/secretref/blob/main/LICENSE)

```json
{
  "database": {
    "host": "db.internal",
    "port": 5432,
    "name": "orders",
    "password": {"env": "DATABASE_PASSWORD"}
  },
  "cache": {
    "url": "redis://cache.internal:6379",
    "password": {"file": "/run/secrets/redis-password"}
  },
  "payments": {
    "api_key": {"command": "op read op://production/stripe/api-key"},
    "webhook_secret": {"env": "STRIPE_WEBHOOK_SECRET"}
  },
  "session": {
    "signing_key": {"file": "/run/secrets/session-key"},
    "timeout_minutes": 30
  },
  "region": {"env": "AWS_REGION", "default": "us-east-1"},
  "smtp_password": {"env": "SMTP_PASSWORD", "required": false},
  "features": ["checkout-v2", "new-dashboard"]
}
```

```python
from secretref import audit, load

config = load("config.json")

config.get("database.host")                     # "db.internal"
config.get("database.port")                     # 5432, an int
config.get("features")                          # ["checkout-v2", ...]
config.get("session.timeout_minutes")           # 30

config.secret("database.password").resolve()    # reads DATABASE_PASSWORD
config.secret("cache.password").resolve()       # reads the mounted file

for finding in audit(config):
    print(finding)
```

Each source is matched to where secrets actually come from: `env` for a
twelve-factor deployment, `file` for a Kubernetes or Docker secret mount,
`command` for a password manager. And the config carries a port that is a
number, a list of feature flags, and nested sections — the three things that
make `.env` start to hurt.

That file is committable. It says where each secret lives, not what it is.

## Documentation

Full documentation is in [`docs/`](https://github.com/janbalitaan/secretref/blob/main/docs/README.md):

| Page | |
| --- | --- |
| [Getting started](https://github.com/janbalitaan/secretref/blob/main/docs/getting-started.md) | Install, a first config, reading a value |
| [Reference forms](https://github.com/janbalitaan/secretref/blob/main/docs/reference-forms.md) | `env`, `file`, `command`, `literal` |
| [Policies](https://github.com/janbalitaan/secretref/blob/main/docs/policies.md) | Bounding what a config may reach |
| [Auditing](https://github.com/janbalitaan/secretref/blob/main/docs/auditing.md) | Finding secrets that ended up inline |
| [Caching](https://github.com/janbalitaan/secretref/blob/main/docs/caching.md) | When resolution is expensive enough to cache |
| [Deployment](https://github.com/janbalitaan/secretref/blob/main/docs/deployment.md) | Docker, Kubernetes, systemd, serverless, a laptop |
| [API reference](https://github.com/janbalitaan/secretref/blob/main/docs/api.md) | Every public name |
| [Security](https://github.com/janbalitaan/secretref/blob/main/docs/security.md) | What an attacker can do |
| [Performance](https://github.com/janbalitaan/secretref/blob/main/docs/performance.md) | Measured costs per reference form |
| [Limitations](https://github.com/janbalitaan/secretref/blob/main/docs/limitations.md) | What it does not do |
| [Comparison](https://github.com/janbalitaan/secretref/blob/main/docs/comparison.md) | Against OmegaConf, Dynaconf and himl |
| [Encryption](https://github.com/janbalitaan/secretref/blob/main/docs/encryption.md) | Why this does no cryptography |

## Install

```bash
pip install secretref
```

Python 3.10+. **No dependencies** — a library that reads your secrets should
be auditable in an afternoon, and every dependency is something else to
audit. `secretref[yaml]` adds YAML support, `secretref[pydantic]` an adapter.

## Why not `.env`

`.env` is fine until the config needs structure. A list of providers, a
nested section, a number that is really a number — all of it arrives as
strings that something has to split and coerce, and the coercion ends up
scattered across the codebase.

JSON and YAML handle structure natively. The problem they introduce is that
the secrets are then sitting in a file beside the code, which is how they
reach a repository. References fix that without giving up structure.

## From a shell

The audit is one line in a pipeline, and the exit status is the interface:

```bash
secretref audit                       # find config.json and check it
secretref audit path/to/config.json
secretref audit --json                # for a tool to consume
secretref audit --strict              # warnings block as well as errors
secretref show                        # list what the config references
secretref policy                      # what the policies permit by default
```

| exit | means |
| --- | --- |
| `0` | nothing blocking |
| `1` | a blocking finding |
| `2` | the command could not run — no config, bad arguments, unparseable file |

The last two are separate on purpose: a pipeline needs to tell "your config
has a problem" from "this tool was used wrongly".

```yaml
# .github/workflows/ci.yml
- run: pip install secretref
- run: secretref audit --strict
```

**It runs nothing.** A command reference is reported as `not verified` rather
than executed, because auditing a config from a pull request is the main use
and resolving one would run whatever the pull request contained. `--resolve
--allow-command op` opts in, for a config you wrote.

It also does not report a command reference as *refused*: this tool's policy
is not your application's, and it has no way to learn what yours permits, so
calling a working config broken would be a false alarm.

## The audit is the point

This is the part that justifies a library rather than a helper function:

```python
for finding in audit(config):
    print(finding)
```

```
error: payments.api_key: a literal secret inside a repository
  try: move it to an environment variable and reference it: {"env": "..."},
       and rotate it, since git history keeps the old value
warning: session.signing_key: a literal secret in a config file
  try: reference it instead of storing it
error: cache.password: refused by policy — file is outside the permitted roots
  try: widen the policy, or point the reference somewhere it permits
note: smtp_password: env 'SMTP_PASSWORD' resolves to nothing
  try: set it, or add "required": false if it is optional
```

Three severities, and the split that matters is *who has to fix it*:

| | means | fix |
| --- | --- | --- |
| `error` on a literal | it may already be published | the config, and rotate the secret |
| `error` on a refusal | the config asks for something policy forbids | the config or the policy |
| `note` | the secret is not where the config said | the deployment |

A refusal is an error whether or not there is a repository above the file,
unlike a literal. It has nothing to do with publishing — the application will
not start.

A policy refusal is never silenced by `required: false` or by a `default`.
Those say the secret may be *absent*; they do not say the config may ask for
something it is not permitted to do.

A literal secret is an **error** when there is a repository above the file,
because such a value is one commit from a remote. Outside a repository the
same value is a warning — careless, but contained.

The distinction matters because the failure being prevented is not a crash.
Nothing breaks when a key is hardcoded; it works perfectly, right up until
the repository is public. No test catches that, which is why it needs a check
of its own.

Wire it into CI and a literal cannot merge:

```python
import sys
from secretref import audit, load

findings = audit(load("config.json"))
for finding in findings:
    print(finding, file=sys.stderr)
sys.exit(1 if any(f.blocking for f in findings) else 0)
```

## Where a secret can come from

| form | reads from | for |
| --- | --- | --- |
| `{"env": "NAME"}` | an environment variable | most things |
| `{"file": "/path"}` | a file's contents | Docker, Kubernetes and systemd secret mounts |
| `{"command": "..."}` | a command's stdout | password managers and cloud secret stores |
| `"a string"` | itself | local experiments, and what the audit objects to |

Each accepts `default` and `required`:

```json
{"smtp_password": {"env": "SMTP_PASSWORD", "required": false}}
{"region":        {"env": "AWS_REGION", "default": "us-east-1"}}
```

`required: false` suits a feature that is off in development — no SMTP server,
no password, and nothing should fail for want of one. `default` suits a value
with a sensible fallback that a deployment may override.

### Local development, in one line

The only setup cost the policies impose, and the only place you are likely to
meet one:

```python
from secretref import FilePolicy

FilePolicy().allow_anywhere()     # secrets live wherever you keep them
```

Nothing is needed for `{"env": ...}`, and nothing is needed for a file under
`/run/secrets` or `/run/credentials` — which is where Docker, Kubernetes and
systemd put them. So a container is confined with no configuration, and a
laptop costs one line.

A `{"command": ...}` reference costs one more, because it is the one form
that runs code:

```python
CommandPolicy().allow("op")        # name what a config may run
```

That is the whole setup. If you meet a refusal, the message names the exact
call that changes it.

### Three policies, one per reference form

Two of the three forms reach outside the process, and the third can be
redirected. Each has a policy, all three are singletons, and only one is off
by default:

```python
from secretref import CommandPolicy, EnvironmentPolicy, FilePolicy

CommandPolicy().allow("op", "vault")           # off by default
FilePolicy().restrict()                        # open by default
EnvironmentPolicy().restrict(prefixes=["MYAPP_"])   # open by default
```

Only `CommandPolicy` starts closed, because only it turns a writable config
into code execution. The other two raise the cost of a mistake rather than
removing a capability, and a library that rejected working configs on upgrade
would get pinned to the version before it.

### Command references are off by default

A `command` reference is the most useful form and the only dangerous one. The
others read a variable or a file; this one starts a process, so **a config
file someone can write is a config file that can run code**.

So it does nothing until you say otherwise, naming what may run:

```python
from secretref import CommandPolicy

CommandPolicy().allow("op", "vault")
```

Without that, a command reference is refused with a message saying how to
enable it. With it, four things hold:

| | |
| --- | --- |
| **Allowlist** | only the executables you named; a config that gains `{"command": "curl ..."}` is refused |
| **Minimal environment** | only `PATH`, `HOME`, `LANG`, `TMPDIR` plus whatever you add. A subprocess given the parent's environment can read every other secret the process holds |
| **Output cap** | 64 KB by default. A secret is short; more is the wrong command or an attempt to exhaust memory |
| **No shell** | split with `shlex` and run directly, so a locator cannot chain commands or open a pipe |

```python
CommandPolicy().allow(
    "op",
    timeout_seconds=5,
    max_output_bytes=4096,
    pass_environment=["OP_SERVICE_ACCOUNT_TOKEN"],
    require_absolute=True,      # a bare name resolves through PATH
)
```

A failing command's stderr is never included in an error message, because a
failing secret tool often prints the secret.

**What this does not do.** An attacker who can edit your config and who is
allowed to run `op` can read everything `op` can read. The policy narrows
what a mistake costs; it does not make a writable config trustworthy. If your
config is attacker-controlled, do not enable command references at all.

## Resolution is lazy, and optionally cached

Loading a config reads no secrets. A file naming twenty of them resolves none
until something asks, so a process that uses one does not need the other
nineteen to exist. That is what lets a single config file serve development
and production.

Every `resolve()` re-reads by default. For `{"env": ...}` that costs nothing;
for `{"command": "op read ..."}` it is a subprocess each time. Caching is
opt-in:

```python
from secretref import ResolutionCache

ResolutionCache().enable(ttl_seconds=300)
```

Off by default because it changes two things you should decide deliberately:
a secret stays in memory after the only read that needed it, and a **rotated
secret keeps serving the old value** until the entry expires. The ttl is how
a long-running process picks up a rotation without restarting;
`ResolutionCache().clear()` is how you force it.

Literals are never cached — reading one costs nothing, so holding it buys
nothing.

## Describing a secret without revealing it

```python
ref = config.secret("database.password")
ref.described()     # "env 'DATABASE_PASSWORD'"
repr(ref)           # "SecretRef(source=env, locator='DATABASE_PASSWORD')"
```

Safe for logs, error messages and anything a user sees. A literal is
described as `"a literal value"` and nothing more, because any part of a
literal is part of a secret. For the same reason `as_dict()` writes a literal
back as `[redacted]` rather than itself.

## Checking everything at once

```python
missing = [path for path, ref in config.secrets().items() if not ref.is_resolvable()]
```

Reports every missing secret at startup instead of failing on the first, so a
new deployment is one round of fixes rather than five.

---

## What someone who can edit your config can do

The policies assume an attacker can write the config file. None of them make
that safe — they bound what it costs.

### Auditing a config you did not write does not execute it

This is the one that matters most, because this README recommends wiring
`audit()` into CI — where the config comes from a pull request.

```python
audit(config)                  # resolves nothing with side effects
audit(config, resolve=True)    # for your own config, at startup
```

An earlier version resolved every reference to check it, and resolving a
command reference **runs** it. A CI check on a pull request was remote code
execution for anyone who had enabled command references for their own use.

Now a command reference is reported as `not verified` rather than run.
Policy refusals and syntax errors are still reported, because those are found
by asking the policy and parsing the string — neither starts anything.

### What each form costs an attacker

| they add | without a policy | with one |
| --- | --- | --- |
| `{"command": "curl ..."}` | runs | refused unless `curl` is allowed |
| `{"command": "op ..."}` where `op` is allowed | reads everything `op` can | **unchanged — this is the real limit** |
| `{"file": "/etc/shadow"}` | reads it | refused; only the secret mounts |
| `{"file": "/run/secrets/other-tenant"}` | reads it | **unchanged — everything in an allowed root is readable** |
| `{"env": "AWS_SECRET_ACCESS_KEY"}` on a rendered field | leaks it | refused if a prefix or allowlist is set |
| a 2 GB command output | read into memory | 64 KB cap |

The two unchanged rows are the honest limit. A policy narrows the blast
radius; it does not make a writable config trustworthy. **If your config is
attacker-controlled, do not enable command references at all.**

### If they can also set PATH

`CommandPolicy().allow("op")` used to permit whatever `op` meant on PATH at
resolution time, so prepending a directory substituted their own script.
Executables are now resolved **when the policy is configured** — while PATH
is still the one the operator started with — and a later substitution is
refused:

```
command 'mytool' resolves to /tmp/evil/mytool, which is not the file this
policy pinned when it was configured. PATH has changed since then.
```

`require_absolute=True` is stricter still: the config itself must name a full
path.

### If they can write inside an allowed root

Then they control what is read, and a symlink out of the root is the obvious
move. Links are resolved before the root check, so that is refused — but an
attacker with write access to `/run/secrets` can read everything in it. That
is not a boundary this library can hold.

## Limitations

Read this before trusting the library with anything that matters.

### The audit cannot find a secret it does not recognize as one

Two checks run, and together they still leave gaps.

**By value.** A credential matching a format its issuer publishes — an AWS
access key ID, a GitHub or Stripe token, a private key block, a connection
string with a password in it — is reported whatever the key is called. These
are named in the finding, so you know what to rotate.

**By key name.** A value under a key like `password` or `api_key` is reported
even when its shape says nothing, which is the only way to catch an internal
credential that has no published format.

What neither finds: a secret with no recognizable shape under a key with no
recognizable name. A password split across two fields. One encoded, or
assembled at runtime. This is a check against carelessness, not against
determination.

The format list is in `patterns.py`, as `KNOWN_SECRET_FORMATS`. Adding one is
a line there and a case in `tests/detection/`.

For scanning a whole repository's *history*, use `gitleaks` or
`detect-secrets`. They answer a different question and answer it better —
this one looks at the config you are about to deploy.

### It does not encrypt anything

A resolved secret is a plain string in your process memory, as it would be
from any config library. This moves the secret out of the file; it does not
protect it once read.

### Environment references can be narrowed

The obvious objection: the process already holds every variable, so reading
one through a reference grants nothing new. True, and beside the point.

The threat is not reaching into the environment. It is redirecting a data
flow that already leaves it:

```json
{"support_email": {"env": "SUPPORT_EMAIL"}}
{"support_email": {"env": "AWS_SECRET_ACCESS_KEY"}}
```

Same process, same variables, no new access — and if the application renders
that field, a key is now on a public page. Every field a config exposes is a
channel: a log line, an error message, an HTTP response, a metrics label.

```python
EnvironmentPolicy().restrict("DATABASE_PASSWORD", "STRIPE_KEY")  # these only
EnvironmentPolicy().restrict(prefixes=["MYAPP_"])                # a namespace
EnvironmentPolicy().restrict(patterns=[r"_PASSWORD$"])           # a convention
EnvironmentPolicy().restrict()                                   # off entirely
```

`EnvironmentPolicy().visible()` lists what a config could currently reach, by
name and never by value — more useful at startup than discovering it from a
refusal.

### File references are confined to the secret mounts

By default a file reference may only read from `/run/secrets` and
`/run/credentials` — where Docker, Kubernetes and systemd actually mount
secrets. A container is therefore protected with no configuration, and still
works. A project keeping secrets elsewhere says so once:

```python
from secretref import FilePolicy

FilePolicy().restrict(Path.home() / ".config" / "myapp")   # add a root
FilePolicy().allow_anywhere()                              # give it up
FilePolicy().reset()                                       # back to default
```

`allow_anywhere()` is named for what it does rather than something softer,
because it is the one call that removes the protection and the call site
should say so.

Five things hold:

| | |
| --- | --- |
| **Allowed roots** | `{"file": "/etc/shadow"}` is refused rather than attempted |
| **Symlinks resolved first** | a link inside a root pointing outside it would otherwise defeat the check |
| **Owner-only available** | `restrict(require_private=True)` refuses a secret readable by group or world, with the `chmod` to fix it. Not the default, because a Kubernetes secret volume is mode 0644 unless the pod spec says otherwise — requiring it would refuse a standard deployment |
| **Size cap** | 64 KB. Pointing a reference at a log file fails rather than reading it |
| **One operation** | the file is opened once and checked through `fstat` on that descriptor, so the inode validated is the inode read |

Kubernetes projected volumes are symlinks, so a link *within* a root is still
read — refusing all links would refuse the main use case.

What this does not fix: an attacker who can write your config and who is
allowed to read `/run/secrets` can read everything in there.

### A `command` reference runs a command

It is split with `shlex` and run without a shell, so the locator cannot chain
commands. It is still a command from a config file, so treat a writable
config as equivalent to code execution.

### Repository detection is a heuristic

The audit looks for `.git`, `.hg` or `.svn` in the file's directory and its
parents, up to a limit. A bare checkout, an unusual VCS layout, or a config
outside the working copy will be judged wrong — in the safe direction, as a
warning rather than an error.

### It is not a schema library

No types, no validation, no coercion beyond what JSON already gives. If you
want those, keep using pydantic and let this resolve the secrets:
`secretref[pydantic]` exists for exactly that.

### `required: false` is quiet by design

A reference that resolves to nothing returns `""` rather than raising. That
is what makes an optional provider optional, and it means a typo in a
variable name looks the same as a deliberately absent one. `audit` reports
both, which is where to catch it.

---

## Contributing

The full guide is in
[CONTRIBUTING.md](https://github.com/janbalitaan/secretref/blob/main/CONTRIBUTING.md),
and security reports go through
[SECURITY.md](https://github.com/janbalitaan/secretref/blob/main/SECURITY.md)
rather than an issue.

Contributions are welcome. The most useful ones:

**Another source.** A secret store with a Python client rather than a CLI, as
an optional extra.

**A smarter audit.** Key names and value shapes that indicate a secret and
are not yet recognized — with the config that fooled it.

**A false positive you hit.** A real one, with the input, is worth more than
a hypothetical.

Every detector needs a test in **both** directions: something it must catch,
and something it must leave alone. A check with only positive tests is the
one that cries wolf in someone else's config.

```bash
git clone https://github.com/janbalitaan/secretref
cd secretref
uv sync
uv run pytest
uv run ruff check src tests
uv run ty check src
uvx complexipy src --max-complexity-allowed 15
```

All four must pass. No function may exceed cognitive complexity 15.

## License

MIT
