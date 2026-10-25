# Security policy

## Reporting a vulnerability

Open a [security advisory](https://github.com/janbalitaan/secretref/security/advisories/new)
rather than a public issue.

If you are not sure whether something qualifies, open the advisory anyway. A
report that turns out to be a non-issue costs a short conversation; a
vulnerability discussed in a public issue cannot be taken back.

Expect an acknowledgement within a week.

## What is in scope

This library reads secrets, so the interesting failures are about what it
reads and what it reveals.

**In scope:**

- A secret appearing in a message, a `repr`, a log line or a finding.
- A policy permitting something it should refuse — a file outside its roots,
  an executable that was not allowed, a variable outside a narrowed
  environment policy.
- `audit()` causing a side effect without `resolve=True`.
- A way to make a command run that the configured policy did not permit.
- A path traversal, symlink or race that reaches a file outside the permitted
  roots.
- Resource exhaustion through a config file — unbounded reads, output or
  recursion.

**Out of scope**, and documented as such in
[docs/limitations.md](docs/limitations.md):

- A resolved secret being plaintext in process memory. Python offers no
  reliable way to pin or wipe a string;
  [docs/encryption.md](docs/encryption.md) explains why encrypting it in
  place would not help.
- Reading everything inside a root the policy was told to permit, or
  everything a permitted executable can reach. A policy narrows the blast
  radius; it does not make a writable config trustworthy.
- The audit missing a secret with no recognizable shape under a key with no
  recognizable name. Worth reporting as a normal issue so the pattern list
  can grow, but it is a known boundary rather than a vulnerability.

## The threat model

[docs/security.md](docs/security.md) states what someone who can edit your
config can do, with and without each policy. The short version: **if your
config file is attacker-controlled, do not enable command references at
all.**

The cases that an earlier version got wrong are kept as tests in
`tests/policy/test_threat_model.py`. Each one is an attack that worked.

## Supported versions

Pre-1.0, only the latest release is supported. A security fix goes out as a
patch release on the current minor version.
