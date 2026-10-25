# Contributing to secretref

The library does one thing: a config file names where its secrets live, and
an audit reports when one is sitting inline instead. Contributions that
sharpen that are more welcome than contributions that widen it.

## Running the checks

```bash
git clone https://github.com/janbalitaan/secretref
cd secretref
uv sync --all-extras
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv run ty check src
uvx complexipy src --max-complexity-allowed 15
```

All of them must pass, and coverage must stay at 100%:

```bash
uv run pytest --cov --cov-fail-under=100
```

CI runs the same commands on Python 3.10 through 3.13.

## The most valuable contributions

### A credential format the audit misses

The highest-value report, because detection by value is what catches a secret
under a key name nobody predicted. Add a line to `KNOWN_SECRET_FORMATS` in
`src/secretref/patterns.py` and a case in `tests/detection/`:

```python
("a Fastly API token", re.compile(r"\b[A-Za-z0-9_-]{32}\b")),
```

Two rules for a new pattern:

1. **Narrow beats broad.** A wrong name on a finding sends someone to rotate
   a key at a provider they do not use. If the format is not distinctive,
   leave it out — key-name matching will still catch it.
2. **Add a negative case too.** Put a plausible non-credential in
   `NOT_CREDENTIALS` and show the pattern does not claim it. An over-broad
   pattern is how an audit gets ignored.
3. **Build the fixture from repeated characters**, as the existing ones do:
   `"sk_live_" + "0" * 24`, not a realistic-looking key. A fixture that reads
   as live is blocked by GitHub's push protection and flagged by every
   scanner a contributor runs — and a library about finding secrets should
   not be the repository that trips secret detection. The patterns match on
   shape, so shape is all a fixture needs.

### A false positive

Equally valuable and easier to miss. If the audit reports something that is
not a secret — another tool's interpolation syntax, a format string, an
identifier that merely looks random — that is a bug. People switch audits off
over false positives.

### A policy that is wrong

If a policy refuses something it should permit, or permits something it
should refuse, say so. Include the deployment shape: the policies are
calibrated so that environment variables, Docker, Kubernetes and systemd need
no configuration at all, and a report that breaks that calibration is
important.

## Code conventions

These are consistent through the package, and a change that follows them
reviews much faster.

- **One class per file.** `models/`, `policies/`, `resolvers/`, `parsers/`,
  `auditors/` and `exceptions/` each hold one concept per module.
- **No mixing classes and functions** in the same module.
- **Absolute imports only**, and all of them at the top of the file.
- **Constants in `constants.py`**, regular expressions in `patterns.py`.
- **Private helpers at the bottom** of the file, after the public surface.
- **Cognitive complexity under 15**, enforced by `complexipy`.
- **Imperative docstrings** — "Return the value", not "Returns the value".
  `ruff` enforces this as D401.
- **Type everything.** `ty` runs in CI with strict checking.

## Writing tests

Tests live in classes, grouped by subject, one subject per file. A test name
should read as the behavior it pins:

```python
class TestCommandPolicy:
    def test_a_command_is_refused_when_the_policy_is_off(self):
        ...
```

Mock assertions use `call_args_list` where the sequence of calls is the thing
under test, rather than checking only the last call.

### Two rules specific to this library

**A test must never assert that a value appears in output.** The whole
package is built so a secret cannot reach a message, a repr or a log line. A
test that checks for a value would pin the opposite.

**A test that resolves a command must say so.** Resolution with side effects
is the sharp edge here; `tests/policy/test_threat_model.py` holds the cases
that cover it, and each one is an attack that worked against an earlier
version.

## What is unlikely to be merged

- **Hierarchical merging, interpolation or layered environments.** OmegaConf,
  Dynaconf and himl do those well. See `docs/comparison.md`.
- **Encryption.** `docs/encryption.md` explains why, and what to use instead.
- **A dependency**, unless it is an optional extra. A library that reads your
  secrets should be auditable in an afternoon.
- **A new reference form** that a `command` reference already covers.

## Reporting a vulnerability

Not through an issue — see [SECURITY.md](SECURITY.md).
