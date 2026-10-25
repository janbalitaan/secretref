# API reference

Everything importable from `secretref`. Nothing else is public.

```python
from secretref import (
    # loading
    Config, load, loads, find_config, repository_root,
    # references
    SecretRef, Source,
    # auditing
    audit, Finding, Severity, Rules,
    # policies
    CommandPolicy, FilePolicy, EnvironmentPolicy,
    # caching
    ResolutionCache,
    # errors
    SecretrefError, ConfigError, ResolutionError,
    CommandNotAllowedError, FileNotAllowedError, VariableNotAllowedError,
    # constants
    REDACTED, __version__,
)
```

## Loading

### `load(path=None, root=".", names=None) -> Config`

Load a config file. With no path, searches `root` for `config.json`,
`config.yaml`, `config.yml`, `config.toml` in that order.

```python
load()                               # find one in the cwd
load("config/production.json")       # name it
load(root="/etc/myapp")              # search elsewhere
load(names=["settings.json"])        # look for a different name
```

Raises `ConfigError` when no file is found or the file will not parse.

### `loads(text, path=None) -> Config`

Parse a config from a string. `path` is for messages only.

```python
loads('{"host": "db.internal"}')
```

### `find_config(root=".", names=None) -> Path | None`

The path `load` would use, or `None`. For deciding whether to load at all.

### `repository_root(start=".") -> Path | None`

The git working copy containing `start`, or `None`. What the audit uses to
decide whether a literal secret is an error or a warning.

## `Config`

### `Config(data, path=None)`

Built from a dict. Normally you call `load` instead.

| Member | Returns | |
| --- | --- | --- |
| `.data` | `Mapping` | the parsed config, read-only |
| `.path` | `Path \| None` | where it came from |
| `.get(dotted, default=None)` | `Any` | a value, or the default |
| `.require(dotted)` | `Any` | a value, raising `ConfigError` if absent |
| `.secret(dotted)` | `SecretRef` | the reference at that path |
| `.secrets()` | `dict[str, SecretRef]` | every reference, by dotted path |
| `Config.load(...)` | `Config` | same as `load()` |
| `Config.loads(...)` | `Config` | same as `loads()` |
| `Config.find(...)` | `Path \| None` | same as `find_config()` |

```python
config.get("database.host")
config.get("database.port", 5432)
config.require("service_name")
config.secret("database.password").resolve()
config.secrets()        # {"database.password": SecretRef(...), ...}
```

`.data` is a read-only view, so a caller cannot mutate the config another
part of the application is reading.

## `SecretRef`

Describes where a secret lives. It is not the secret.

### `SecretRef.parse(value) -> SecretRef`

```python
SecretRef.parse({"env": "DATABASE_PASSWORD"})
SecretRef.parse({"file": "/run/secrets/key"})
SecretRef.parse({"command": "op read op://prod/db/password"})
SecretRef.parse({"literal": "development-only"})
SecretRef.parse("an-inline-value")                  # a literal
SecretRef.parse({"env": "SMTP_PASSWORD", "required": False})
SecretRef.parse({"env": "AWS_REGION", "default": "us-east-1"})
```

| Member | Returns | |
| --- | --- | --- |
| `.source` | `Source` | `ENV`, `FILE`, `COMMAND` or `LITERAL` |
| `.locator` | `str` | the variable name, path, command or value |
| `.default` | `str \| None` | the fallback, if any |
| `.required` | `bool` | whether absence is an error |
| `.resolve(allow_literal=True)` | `str` | **fetches the value** |
| `.described()` | `str` | a safe description, carrying no value |
| `.is_resolvable()` | `bool` | whether it resolves — **may have side effects** |
| `.refusal()` | `str` | why the policy forbids it, or empty. Resolves nothing. |
| `.malformed()` | `str` | why it cannot work at all, or empty |
| `.has_side_effects()` | `bool` | `True` only for a command |
| `.as_dict()` | `dict` | the config form it came from |

```python
reference.described()        # "env 'DATABASE_PASSWORD'"
reference.refusal()          # "" when permitted
reference.has_side_effects() # True for a command
```

`repr()` and `str()` never include the value, so a reference is safe in a
traceback, a log line or pytest output.

### Checking without triggering

```python
if reference.has_side_effects():
    print("not checking this one")
elif problem := reference.refusal():
    print(f"the policy forbids it: {problem}")
elif not reference.is_resolvable():
    print("it resolves to nothing")
```

`refusal()` and `malformed()` ask the policy and parse the string. Neither
runs anything. `is_resolvable()` **does** resolve, so a command reference
runs — which is why `audit()` does not call it by default.

## `audit(config, *, resolve=False, rules=None) -> list[Finding]`

```python
audit(config)                  # resolves nothing with side effects
audit(config, resolve=True)    # also verifies each secret resolves
audit(config, rules=my_rules)  # looks for what you tell it to
```

See [auditing](auditing.md).

## `Rules`

What the audit looks for, as data you can change. Frozen; every adjustment
returns a new set.

```python
from secretref import Rules

rules = (
    Rules.default()
    .with_formats({"a Fastly API token": re.compile(r"...")})
    .with_secret_keys(["access_pass", "signing_material"])
    .with_placeholders([r"^__[A-Z_]+__$"])
    .with_repository_markers((*REPOSITORY_MARKERS, ".jj"))
    .with_minimum_length(12)
)
audit(config, rules=rules)
```

| Method | |
| --- | --- |
| `.with_formats(add, *, replace_named, without)` | credential formats |
| `.with_secret_keys(names)` | key names that mean "credential" |
| `.with_placeholders(patterns)` | shapes that mean "not filled in yet" |
| `.with_repository_markers(markers)` | what counts as a working copy |
| `.with_minimum_length(length)` | the bar for "too short to judge" |
| `.describe()` | safe to log |

Fields: `formats`, `secret_key`, `placeholders`, `repository_markers`,
`min_secret_length`, `extra_key_names`.

`with_formats` and `with_secret_keys` **extend** rather than replace, because
a caller adding one name almost never means "and stop recognizing password".
A name in `replace_named` or `without` that is not present raises, since the
usual cause is a typo. See [extending](extending.md).

## `Finding`

| Member | Returns | |
| --- | --- | --- |
| `.severity` | `Severity` | `ERROR`, `WARNING` or `NOTE` |
| `.path` | `str` | the dotted path |
| `.message` | `str` | what is wrong. Never a value. |
| `.remedy` | `str` | what to do about it |
| `.blocking` | `bool` | `True` for an error |
| `.as_dict()` | `dict` | for JSON output |

## `Severity`

```python
Severity.ERROR      # "error"
Severity.WARNING    # "warning"
Severity.NOTE       # "note"

sorted(findings, key=lambda f: f.severity)      # most severe first
Severity.worst(f.severity for f in findings)    # or None
Severity.ERROR.rank                             # 0
```

Values stay strings because they appear in output; ordering is defined
separately so the wire format is not hostage to the comparison.

## `Source`

```python
Source.ENV        # "env"
Source.FILE       # "file"
Source.COMMAND    # "command"
Source.LITERAL    # "literal"
```

## Policies

Each is a process-wide singleton. See [policies](policies.md).

### `CommandPolicy`

```python
CommandPolicy().allow("op")
CommandPolicy().allow(
    "op", "vault",
    timeout_seconds=10,
    max_output_bytes=65536,
    pass_environment=["HOME", "OP_SERVICE_ACCOUNT_TOKEN"],
    working_directory="/opt/app",
    require_absolute=False,
)
CommandPolicy().forbid()
CommandPolicy().enabled        # False by default
CommandPolicy().describe()
```

### `FilePolicy`

```python
FilePolicy().restrict("/etc/myapp/secrets", require_private=True, max_bytes=65536)
FilePolicy().allow_anywhere()
FilePolicy().reset()
FilePolicy().roots
FilePolicy().describe()
```

### `EnvironmentPolicy`

```python
EnvironmentPolicy().restrict("DATABASE_URL", prefixes=["MYAPP_"], patterns=[r"^SVC_\w+$"])
EnvironmentPolicy().relax()
EnvironmentPolicy().permits("MYAPP_TOKEN")
EnvironmentPolicy().visible()
EnvironmentPolicy().restricted
EnvironmentPolicy().describe()
```

## `ResolutionCache`

```python
ResolutionCache().enable(ttl_seconds=300)
ResolutionCache().disable()
ResolutionCache().clear()
ResolutionCache().enabled
ResolutionCache().stats()
```

See [caching](caching.md).

## Errors

```
SecretrefError                    everything below inherits this
├── ConfigError                   no config, will not parse, missing key
├── ResolutionError               a secret could not be fetched
├── CommandNotAllowedError        the command policy refused
├── FileNotAllowedError           the file policy refused
└── VariableNotAllowedError       the environment policy refused
```

Catching `SecretrefError` catches everything this library raises. No message
ever contains a secret's value.

```python
from secretref import SecretrefError

try:
    password = config.secret("database.password").resolve()
except SecretrefError as error:
    logger.error("configuration problem: %s", error)
    raise SystemExit(1) from error
```

## Constants

```python
REDACTED        # "[redacted]", what a value is replaced with
__version__     # the installed version
```

Every constant that affects a decision is reachable at runtime, so a value
that is wrong for one codebase does not wait for a release:

| Constant | Where to change it |
| --- | --- |
| `CONFIG_NAMES` | `load(names=...)`, or `Config.NAMES` on a subclass |
| `KNOWN_SECRET_FORMATS` | `Rules.with_formats` |
| `SECRET_KEY` | `Rules.with_secret_keys` |
| `PLACEHOLDERS` | `Rules.with_placeholders` |
| `MIN_SECRET_LENGTH` | `Rules.with_minimum_length` |
| `REPOSITORY_MARKERS` | `Rules.with_repository_markers`, `Repository.root(markers=...)` |
| `MAX_PARENTS_SEARCHED` | `Repository.root(max_parents=...)` |
| `COMMAND_TIMEOUT_SECONDS` | `CommandPolicy.allow(timeout_seconds=...)` |
| `MAX_COMMAND_OUTPUT_BYTES` | `CommandPolicy.allow(max_output_bytes=...)` |
| `MINIMAL_ENVIRONMENT` | `CommandPolicy.allow(pass_environment=...)` |
| `SECRET_MOUNTS` | `FilePolicy.restrict(roots=...)` |
| `MAX_SECRET_FILE_BYTES` | `FilePolicy.restrict(max_bytes=...)` |

## Command line

See [auditing](auditing.md) for the full description.

```bash
secretref audit [PATH] [--root DIR] [--json] [--strict] [--resolve] [--allow-command NAME]
secretref show  [PATH] [--root DIR] [--json]
secretref policy
```

Also `python -m secretref`, for when the console script is not on `PATH`.
