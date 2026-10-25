# Changelog

This project follows [semantic versioning](https://semver.org). Until 1.0.0
the public API may change in a minor release; anything that would break a
caller is listed under **Changed** with what to do about it.

## [Unreleased]

## [0.1.0] — 2026-10-26

First release.

### Added

- Config files that say where a secret lives rather than holding it. Four
  reference forms — `{"env": ...}`, `{"file": ...}`, `{"command": ...}` and
  `{"literal": ...}` — usable anywhere a value would be.
- `audit()`, which reports secrets a config should only be pointing at. It
  resolves nothing with side effects, so auditing a config from a pull
  request runs none of its commands; `resolve=True` opts in for a config of
  your own.
- Credential detection by published format, so an AWS access key ID, a GitHub
  or Stripe token, a private key block or a connection string with a password
  is reported whatever the key is called — and named, so you know what to
  rotate. Key names are matched as well, for internal credentials with no
  published shape.
- Another tool's interpolation (`@format {env[X]}`, `${VAR}`,
  `{{ssm.path(...)}}`, `%(name)s`) is recognized as a reference rather than
  reported as a hardcoded secret, so a config read by a settings library as
  well can be audited.
- A command line: `secretref audit`, `show` and `policy`. The audit is one
  line in a pipeline, exiting 0 for nothing blocking, 1 for a blocking
  finding, and 2 when the command could not run at all — the last two
  separate so a pipeline can tell a bad config from bad usage.
- Three policies bounding what a config may reach, one per reference form.
  Commands are off until you name the executables you trust; files are
  confined to `/run/secrets` and `/run/credentials`; environment references
  are open. Environment variables, Docker, Kubernetes and systemd need no
  policy at all.
- Executables are resolved when a command policy is configured, not when a
  reference is used, so a later change to `PATH` cannot substitute a
  different binary for an allowed name.
- Policy settings are immutable snapshots swapped in one assignment, so a
  thread reading a policy while another configures it never sees a
  half-applied, more permissive mixture.
- `ResolutionCache`, opt-in, for when a `command` reference would otherwise
  be a subprocess per access.
- Values never appear in a message, a `repr` or a log line. A command's
  arguments and a failed command's stderr are both withheld, since either can
  carry the secret.
- `Finding.as_dict()` and an ordering on `Severity`, so findings can be
  consumed by a tool and reduced to one verdict.
- JSON support with no dependencies; YAML through the `yaml` extra.
- Python 3.10 and newer. Fully typed, with `py.typed`.

[Unreleased]: https://github.com/janbalitaan/secretref/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/janbalitaan/secretref/releases/tag/v0.1.0
