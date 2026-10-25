# Policies

A policy bounds what a config file is allowed to reach. One per reference
form, each a process-wide singleton configured once at startup.

```python
from secretref import CommandPolicy, EnvironmentPolicy, FilePolicy
```

The defaults are chosen so the common deployments need no policy at all:

```bash
$ secretref policy
  command references: off
  file references: /run/secrets, /run/credentials, any permissions, capped at 65536 bytes
  environment references: any variable
```

## What setting one costs you

Measured against real deployment shapes:

| Deployment | Lines of policy |
| --- | --- |
| Environment variables only | **0** |
| Docker / Docker Swarm secrets | **0** |
| Kubernetes projected secrets | **0** |
| systemd `LoadCredential` | **0** |
| A laptop reading `./secrets/` | **1** |
| A password-manager CLI | **1** |

If you deploy the ordinary way, you configure nothing.

## `CommandPolicy`

Off by default. A config that can name a command can name any command, so
this is the one form you have to opt into.

```python
CommandPolicy().allow("op")                       # by name
CommandPolicy().allow("/usr/local/bin/op")        # by absolute path
CommandPolicy().allow("op", "aws", "vault")       # several
CommandPolicy().forbid()                          # back to off
```

Everything the command runs under:

```python
CommandPolicy().allow(
    "op",
    timeout_seconds=5,              # default 10
    max_output_bytes=4096,          # default 65536
    pass_environment=["HOME", "OP_SERVICE_ACCOUNT_TOKEN"],
    working_directory="/opt/app",
    require_absolute=True,          # the config must name a full path
)
```

**Executables are pinned when you call `allow()`**, not when a reference is
resolved. `allow("op")` runs `shutil.which("op")` immediately and stores the
absolute path, so a later change to `PATH` cannot substitute a different
file:

```
command 'op' resolves to /tmp/evil/op, which is not the file this policy
pinned when it was configured. PATH has changed since then.
```

A name that is not installed yet falls back to being checked by name, so a
container that configures its policy before installing the tool still works.

### What the command does not inherit

Only the variables `pass_environment` names, plus a minimal set needed for a
program to start. A subprocess handed the parent's whole environment can read
every other secret the process holds.

## `FilePolicy`

Confined by default to `/run/secrets` and `/run/credentials` — where Docker,
Kubernetes and systemd mount secrets.

```python
FilePolicy().restrict("/etc/myapp/secrets")       # replace the roots
FilePolicy().restrict("./secrets", require_private=False)
FilePolicy().allow_anywhere()                     # no confinement
FilePolicy().reset()                              # back to the defaults
```

| Argument | Meaning |
| --- | --- |
| `*roots` | the directories a reference may read under |
| `require_private` | refuse a file that is group- or world-readable |
| `max_bytes` | refuse a file larger than this (default 64 KiB) |

Symbolic links are resolved before the root is checked, so a link inside a
permitted root pointing out of it is refused. The file is opened once with
`O_NOFOLLOW` and validated with `fstat` on the open descriptor, so the file
that was checked is the file that is read.

`require_private=False` is the right call on a laptop, where a `./secrets/`
directory under a normal umask is group-readable and refusing it would only
teach you to turn the policy off entirely.

## `EnvironmentPolicy`

Open by default: a process's environment is already visible to that process,
so reading a variable it was given is not an escalation.

It is worth narrowing when a config is **rendered into output** — a template,
a debug page, an error report — because then a reference is a way of asking
for a variable that was never meant to be read:

```python
EnvironmentPolicy().restrict(prefixes=["MYAPP_"])
EnvironmentPolicy().restrict("DATABASE_URL", "STRIPE_KEY")
EnvironmentPolicy().restrict(patterns=[r"^SERVICE_\w+_TOKEN$"])
EnvironmentPolicy().relax()                       # back to open
```

All three narrowings combine: a variable passes if it matches any of them.

```python
EnvironmentPolicy().permits("MYAPP_TOKEN")        # True
EnvironmentPolicy().visible()                     # what is readable now
```

## When a policy refuses

Every refusal raises, naming the reference and the exact call that would
permit it:

```python
from secretref import CommandNotAllowedError, FileNotAllowedError, VariableNotAllowedError
```

```
command 'op' was refused: command references are off by default. Enable
them deliberately with CommandPolicy().allow("your-tool"), naming the
executables a config is permitted to run.
```

A refusal is never silent, and `required: false` does not swallow one. A
reference the policy forbids is a configuration mistake, not an absent
secret.

## Where to configure them

Once, at startup, before anything loads a config:

```python
# app/startup.py
from secretref import CommandPolicy, FilePolicy, load


def configure() -> None:
    """Bound what a config may reach, before reading one."""
    CommandPolicy().allow("op", timeout_seconds=5)
    FilePolicy().restrict("/etc/myapp/secrets")


configure()
settings = load("config.json")
```

They are singletons, so this applies process-wide and a library deeper in the
stack cannot widen it by constructing its own.

Settings are swapped as an immutable snapshot in a single assignment, so a
thread reading a policy while another configures it sees the old settings or
the new ones — never a half-applied mixture, which in the worst ordering
would be more permissive than either.
