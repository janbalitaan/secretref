# Security

## What this library protects

A config file that says *where* a secret lives rather than holding it. That
is the only guarantee, and everything below is about its edges.

## Design commitments

These do not change between versions:

1. **A value never appears in a message, a repr or a log line.** Errors name
   the reference. A finding carries no value. `repr(SecretRef)` prints the
   source and a safe description, never the locator of a literal.
2. **A command's arguments are never quoted in an error.** `--token=...` is a
   real pattern, so only the executable is named.
3. **A failing command's stderr is not included.** A secrets CLI often prints
   the value it was reading when it failed.
4. **Auditing has no side effects** unless you pass `resolve=True`.

## What someone who can edit your config can do

The policies assume an attacker can write the config file. None of them make
that safe — they bound what it costs.

### Auditing a config you did not write does not execute it

The one that matters most, because the documented use is a CI check, where
the config comes from a pull request.

```python
audit(config)                  # resolves nothing with side effects
audit(config, resolve=True)    # for your own config, at startup
```

An earlier version resolved every reference to check it, and resolving a
command reference **runs** it. A CI check on a pull request was remote code
execution for anyone who had enabled command references for their own use.

A command reference is now reported as `not verified` rather than run.
Policy refusals and syntax errors are still reported, because those come from
asking the policy and parsing a string.

### What each form costs an attacker

| they add | without a policy | with one |
| --- | --- | --- |
| `{"command": "curl ..."}` | runs | refused unless `curl` is allowed |
| `{"command": "op ..."}` where `op` is allowed | reads everything `op` can | **unchanged — the real limit** |
| `{"file": "/etc/shadow"}` | reads it | refused; only the secret mounts |
| `{"file": "/run/secrets/other-tenant"}` | reads it | **unchanged — an allowed root is readable** |
| `{"env": "AWS_SECRET_ACCESS_KEY"}` on a rendered field | leaks it | refused if narrowed |
| a 2 GB command output | read into memory | 64 KB cap |

The two unchanged rows are the honest limit. **If your config is
attacker-controlled, do not enable command references at all.**

### If they can also set PATH

`CommandPolicy().allow("op")` used to permit whatever `op` meant on `PATH` at
resolution time, so prepending a directory substituted their own script.
Executables are now resolved **when the policy is configured** — while `PATH`
is still the one the operator started with — and a later substitution is
refused:

```
command 'mytool' resolves to /tmp/evil/mytool, which is not the file this
policy pinned when it was configured. PATH has changed since then.
```

`require_absolute=True` is stricter: the config itself must name a full path.

### If they can write inside an allowed root

Then they control what is read, and a symlink out of the root is the obvious
move. Links are resolved before the root check, so that is refused — but an
attacker with write access to `/run/secrets` can read everything in it. That
is not a boundary this library can hold.

## Implementation notes

### Files are opened once

`FilePolicy.read()` opens with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` and
validates with `fstat` on the open descriptor. Checking a path and then
opening it separately leaves a window in which the inode that was checked is
not the inode that is read — and a path inside a secret mount is where that
matters.

### Commands run without a shell

Split with `shlex` and executed directly, so a locator cannot smuggle in a
pipeline, a redirect or a second command. The subprocess gets only the
environment variables the policy names: a child handed the parent's whole
environment can read every other secret the process holds.

### Policies are swapped, not mutated

`allow()` builds a new frozen settings object and assigns it in one
statement. Assigning several fields in sequence meant a concurrent reader
could see `enabled=True` with an empty allowlist — which, under the
"empty means any" rule that applied then, permitted everything.

### A read-only view of the config

`Config.data` returns a `MappingProxyType`, so a caller cannot mutate the
config another part of the application is reading.

## Reporting a vulnerability

Open a GitHub security advisory rather than a public issue. If you are not
sure whether something counts, open the advisory anyway.

## What this does not do

See [limitations](limitations.md). The short version: it does not encrypt
anything, it does not scan git history, and it cannot find a secret it does
not recognize as one.
