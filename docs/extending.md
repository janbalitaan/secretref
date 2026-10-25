# Extending without waiting for a release

A pattern in a library is a liability on someone else's release cycle. A
vendor publishes a credential format nobody has covered yet. A shipped
pattern fires on something harmless in one codebase. A team names its
credential keys something the key-name rule does not recognize. A repository
uses a version control system this version has not heard of.

None of those should mean opening an issue and waiting, so none of them do.

## `Rules`

What the audit looks for, as data rather than constants. Frozen, and every
adjustment returns a new set — a shared mutable policy is a bug class this
library has already been bitten by once.

```python
import re
from secretref import Rules, audit, load

rules = (
    Rules.default()
    .with_formats({"a Fastly API token": re.compile(r"\b[A-Za-z0-9_-]{32}\b")})
    .with_secret_keys(["access_pass", "signing_material"])
    .with_placeholders([r"^__[A-Z_]+__$"])
)
findings = audit(load("config.json"), rules=rules)
```

With the shipped rules that config produces nothing. With these it produces
two errors. The difference is not a bug in either — it is a codebase whose
conventions a library could not have known.

## Credential formats

The shipped list covers eighteen published formats. Adding a nineteenth:

```python
Rules.default().with_formats({"a Fastly API token": re.compile(r"...")})
```

Correcting one that is out of date, keeping its position — the first match
wins, and the order places narrower patterns before wider ones:

```python
Rules.default().with_formats(
    replace_named={"an AWS access key ID": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")}
)
```

Dropping one that misfires here:

```python
Rules.default().with_formats(without=("a generic 32-character hex string",))
```

A name in `replace_named` or `without` that is not present raises, listing
what is available. The usual cause is a typo, and silently doing nothing
would leave you believing a format was changed when it was not.

## Key names

The shipped rule recognizes `password`, `secret`, `token`, `api_key` and
their common variants. For a convention it does not know:

```python
Rules.default().with_secret_keys(["access_pass", "shared_secret_v2"])
```

Matched against the final segment of a dotted path, case-insensitively, and
word-bounded so `api_key_id` is not caught by `api_key`.

**Extends rather than replaces.** A caller adding one name almost never means
"and stop recognizing password", and the version that silently did would be a
security regression dressed as a convenience. To replace the rule outright,
construct `Rules(secret_key=my_pattern)`.

## Placeholder shapes

A value matching one of these is reported as a note rather than an error,
because `CHANGEME` in a config is a different problem from a real key:

```python
Rules.default().with_placeholders([r"^__[A-Z_]+__$", r"^<<set-by-terraform>>$"])
```

A pattern that will not compile raises here, naming it, rather than at match
time when you have no idea which entry was wrong.

## Repository markers

The severity of a finding turns on this. A literal secret inside a working
copy is one commit from a remote and git history keeps it after the fix; the
same value outside one is careless but contained.

So a repository this version does not recognize means real findings reported
one level too quietly:

```python
from secretref.constants import REPOSITORY_MARKERS

Rules.default().with_repository_markers((*REPOSITORY_MARKERS, ".jj", ".fossil"))
```

Replaces rather than extends, because a caller naming their markers knows
which ones apply — hence spreading the shipped tuple to add to it.

## The minimum length

Below it, a value under a credential-shaped key is a note rather than an
error: a short string there is more often a flag or an abbreviation than a
secret.

```python
Rules.default().with_minimum_length(12)   # a codebase full of short enums
Rules.default().with_minimum_length(4)    # real short secrets are getting through
```

## Every constant, and where to change it

| Constant | Where |
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

## What is deliberately not adjustable

**The reference vocabulary** — `env`, `file`, `command`, `literal`. A new
source is not a pattern but a resolver, with its own policy and its own
failure modes, and a config that could name an arbitrary resolver is a config
that could name an arbitrary code path.

**That `audit()` resolves nothing with side effects by default.** Not by a
setting a config file could reach. Resolving a command reference runs it, and
auditing a config you did not write is the main use for this.

**That a policy cannot be widened once locked.** The point of locking is that
later code cannot undo it.

## Where to put your configuration

A policy is code. It belongs beside your application, not in user input — a
config file that could set its own audit rules could set them to nothing:

```python
# app/secrets.py
RULES = (
    Rules.default()
    .with_secret_keys(OUR_KEY_NAMES)
    .with_repository_markers((*REPOSITORY_MARKERS, ".jj"))
)

def check() -> list[Finding]:
    return audit(load(), rules=RULES)
```

One module, imported where it is needed, and `RULES.describe()` logs what it
decided at startup.
