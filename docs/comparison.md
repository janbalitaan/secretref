# How this compares

secretref is not a configuration framework. It is a secret-reference layer
with an audit and a policy model, and it composes with the frameworks rather
than replacing them.

## What each tool is for

| | secretref | OmegaConf | Dynaconf | himl |
| --- | --- | --- | --- | --- |
| Hierarchical merging | — | **yes** | **yes** | **yes** |
| Variable interpolation | — | **yes** | **yes** | **yes** |
| Structured-config type safety | — | **yes** | — | — |
| Layered environments | — | — | **yes** | **yes** |
| Framework integration | — | — | **Django, Flask** | — |
| Secret backends | env, file, command | — | **Vault, Redis** | **AWS SSM, S3, Vault** |
| **Audits a config for leaked secrets** | **yes** | — | — | — |
| **Policy over what a config may read** | **yes** | — | — | — |
| **Safe to audit an untrusted config** | **yes** | n/a | n/a | n/a |

Pick the framework for what it is good at. The last three rows are what this
library adds.

## OmegaConf

A hierarchical YAML config system with interpolation and runtime type safety
through structured configs. The foundation of Hydra, and the standard in ML
work.

It is not a secrets tool. Environment variables are one merge source among
several; there is no notion of a secret, no audit and no access control.

**Use both.** Let OmegaConf compose and type-check your configuration, and
point secretref's audit at the files:

```bash
secretref audit conf/config.yaml
```

## Dynaconf

The closest overlap, and much broader: layered settings, several file
formats, type casting, validators, a CLI, Django and Flask integration, and
Vault and Redis backends. If you want a settings framework, it is the more
complete choice.

Its answer to secrets is a separate `.secrets.toml` that you add to
`.gitignore`. That is sound advice and it is the whole of the protection —
there is no check that a key did not end up in `settings.toml` instead, and
no mechanism bounding what a loader may reach.

**Use both.** Dynaconf for settings, secretref's audit as the check that
nothing landed in the wrong file:

```bash
secretref audit settings.yaml
secretref audit .secrets.yaml   # even the right file is worth checking
```

## Adobe himl

Deep-merges hierarchical YAML from defaults down to the most specific values,
with secret interpolation from AWS SSM, S3 and Vault. Aimed at Kubernetes and
Terraform configuration, inspired by Puppet's Hiera.

Strong at what it does, and that overlaps little with this. It has no audit,
and its `{{ssm.path(...)}}` interpolation will reach wherever the config says
— a config file is trusted input.

**Use both.** himl to produce the merged config, secretref to audit it before
it ships.

## The three things that are actually different

### 1. It audits

None of the others will tell you a secret is sitting in your config file.

```bash
$ secretref audit settings.yaml
error: default.database.password: a Stripe secret key inside a repository, so git history keeps it
  try: rotate this credential, then reference it instead of storing it: {"env": "YOUR_VAR"}
```

Exit status 1, so it is one line in CI. It reads JSON and YAML and does not
care which library owns the file, so this works on a Dynaconf, Hydra or himl
config. Another tool's interpolation syntax is recognized as a reference, not
reported as a hardcoded value.

### 2. It treats a config file as partially untrusted

Every other tool here assumes the config is trusted input, which is
reasonable right up until the config arrives in a pull request, or from a
template, or from another team.

Command references are off until you name the executables you trust. File
references are confined to the secret mounts. Executables are pinned when the
policy is configured, so a later `PATH` change cannot substitute a different
binary.

This costs nothing for an ordinary deployment: environment variables, Docker,
Kubernetes and systemd all need **zero** lines of policy.

### 3. Auditing does not execute anything

A tool that validated a config by resolving it would run its commands. This
one separates asking the policy from fetching the value, so checking a
config from a pull request is safe:

```python
audit(config)                 # runs nothing
audit(config, resolve=True)   # for a config of your own
```

## When not to use this

- **You need hierarchical merging or interpolation.** It does not do either.
  Use OmegaConf, Dynaconf or himl, and audit the result.
- **You want a settings framework** with validators, type casting and
  framework integration. Dynaconf is more complete.
- **Your secrets live in Vault, SSM or Secrets Manager** and you want a
  native client. This shells out to their CLI, which is a dependency and a
  subprocess. Dynaconf's Vault backend or himl's SSM support may suit better.
- **You want history scanning.** `gitleaks` and `detect-secrets` scan a
  repository's past; this looks at the config you are about to deploy.

## Honest summary

The edge is real but narrow. secretref does one thing the others do not — it
treats the config file as something to lint and something to distrust — and
it does much less than any of them in every other respect.

If you already use one of these, the sensible shape is to keep it and add
`secretref audit` to CI.
