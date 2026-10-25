# Encryption

Short answer: **this library does no cryptography, and that is deliberate.**
It composes with the tools that do.

"Encrypt the secrets" sounds strictly better than not encrypting them, so it
is worth separating the four things it can mean. Three are not worth doing.
One is, and it already works.

## Encrypting a resolved value in memory

**Not worth doing.** To decrypt a value you need the key, and the key would
live in the same process as the ciphertext. An attacker who can read your
process memory reads both.

This is the version that looks like security and is not. A library offering
it would be making a claim it cannot keep, and the people most likely to
trust that claim are the ones least able to check it.

## Wiping a secret from memory after use

**Not worth doing in Python, for a specific reason.**

A `str` is immutable and cannot be overwritten. You can hold a secret in a
`bytearray` and zero it, which is a real improvement in a language where you
control every copy — but Python does not let you:

```python
secret = bytearray(b"the-password")
connect(secret.decode())    # this creates an immutable str copy
secret[:] = b"\x00" * len(secret)   # the bytearray is wiped
                                    # the str copy is not, and you cannot reach it
```

The moment the value is used as a string — a connection URL, an HTTP header,
a query parameter — the interpreter has made a copy you have no handle on.
Zeroing the original then protects one copy out of several and reports
success.

An API of `bytearray` everywhere would cost every caller real clarity and buy
a guarantee that does not survive first use. If a secret must not be readable
by whatever can read your process, that needs a different mechanism
altogether: an HSM, an enclave, or a service that holds the key and performs
the operation for you.

## Encrypting the resolution cache

**Not worth doing.** Same reasoning as the first: the key would sit in the
process that holds the ciphertext.

The cache's honest description is in [caching](caching.md) — it holds
plaintext secrets for the length of its TTL, which is why it is off by
default and why the trade is written down rather than hidden behind
encryption that would not change it.

## Encrypting the config file itself

**Genuinely useful, genuinely not this library's job.**

This is the one that is not theater. Committing an encrypted config means a
leaked repository, a stolen laptop or an old backup is useless without the
key. The storage and the runtime are separate things, and encryption at rest
protects the first even when the second is sound. That is a real gain, and
compliance regimes often require it.

Two reasons it does not belong here.

**It conflicts with the premise.** This library exists so a config file does
not hold the secret at all. Encryption's premise is that the config holds the
secret, scrambled. If the value is not in the file, there is nothing in the
file to encrypt — the two approaches solve the same problem differently
rather than stacking.

**Doing it well is a whole project.** Key management, key rotation, multiple
recipients, partial-file encryption, audited primitives. SOPS, age, git-crypt
and sealed-secrets each do this properly. A hand-rolled `encrypt()` in a
config library would be worse than any of them, and would be trusted because
it was there.

### It already works

A `command` reference reads from whatever can decrypt, which is every one of
those tools. No new code, no new reference form:

```json
{
  "database": {
    "password": {
      "command": "sops -d --extract '[\"database\"][\"password\"]' secrets.enc.yaml"
    }
  }
}
```

```python
CommandPolicy().allow("sops")
```

With `age`:

```json
{"password": {"command": "age -d -i /run/secrets/age.key secret.age"}}
```

With `gpg`:

```json
{"password": {"command": "gpg --batch --quiet --decrypt secret.gpg"}}
```

```python
CommandPolicy().allow("gpg", pass_environment=["HOME", "PATH"])
```

All three keep the useful property: `audit()` reports the reference without
running it, so auditing a config from a pull request still decrypts nothing.

```
note: database.password: command 'gpg' was not verified
  try: resolving it would run a command, which an audit does not do
```

### Where the decryption key comes from

This is the part worth being clear about, because it is what encryption does
not solve.

Something has to hold the key, and the key is a secret. In the `gpg` example
the passphrase comes from `/run/secrets/gpg-passphrase` — a secret file,
delivered by the platform, the same way an unencrypted secret would have
been.

Encryption at rest **moves** the problem from many secrets to one key. That
is a worthwhile move: one key is easier to protect, rotate and audit than
fifty passwords, and it is why the pattern is popular. But it does not remove
the need for a root secret, and a design that claims otherwise has simply
not looked for it.

Which is the same reason this library resolves references instead of storing
values. At the bottom of either approach something trusted hands you one
secret. The difference is how much is sitting in your repository in the
meantime.

## What to use instead

| You want | Use |
| --- | --- |
| Secrets encrypted in git, GitOps-style | **SOPS** with age or KMS, read through a `command` reference |
| Whole files encrypted in git | **git-crypt** |
| Kubernetes secrets committed safely | **sealed-secrets** or **External Secrets Operator** |
| A managed secret store | **Vault**, **AWS Secrets Manager**, **1Password** — all have CLIs |
| Secrets out of the config entirely | this library, with `env` or `file` references |

The last row needs no encryption because there is nothing in the file to
encrypt. That is the cheapest answer when it fits, and it fits more often
than people expect.

## Summary

- **In memory:** no. The key would be beside the ciphertext.
- **Wiping memory:** no. Python copies the value before you can wipe it.
- **The cache:** no, for the same reason as memory.
- **The config file at rest:** yes, and use SOPS or age. Read it through a
  `command` reference; the policy and the audit still apply.

This library's contribution is making the secret absent rather than
protected. Those are different goals, and absent is the stronger one when it
is available.
