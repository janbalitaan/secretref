# Deployment

A recipe per platform. The short version: if you deploy the ordinary way,
you configure no policy at all.

## Environment variables

The default on most platforms, and nothing to set up.

```json
{"database": {"password": {"env": "DATABASE_PASSWORD"}}}
```

```bash
export DATABASE_PASSWORD=...
python -m myapp
```

**Policy needed: none.** Environment references are open by default.

## Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
CMD ["python", "-m", "myapp"]
```

```bash
docker run -e DATABASE_PASSWORD=... myapp
```

With Docker secrets, which keeps the value out of the environment:

```yaml
# compose.yaml
services:
  app:
    image: myapp
    secrets:
      - db_password
secrets:
  db_password:
    file: ./db_password.txt
```

```json
{"database": {"password": {"file": "/run/secrets/db_password"}}}
```

**Policy needed: none.** `/run/secrets` is permitted by default.

## Kubernetes

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: myapp
      volumeMounts:
        - name: secrets
          mountPath: /run/secrets
          readOnly: true
  volumes:
    - name: secrets
      secret:
        secretName: myapp-secrets
```

```json
{"database": {"password": {"file": "/run/secrets/database-password"}}}
```

**Policy needed: none.**

A file beats an environment variable here: a projected secret updates without
restarting the pod, and it does not appear in `/proc/<pid>/environ` or get
inherited by a child process.

## systemd

```ini
[Service]
LoadCredential=db_password:/etc/myapp/db_password
ExecStart=/usr/bin/python3 -m myapp
```

```json
{"database": {"password": {"file": "/run/credentials/myapp.service/db_password"}}}
```

**Policy needed: none.** `/run/credentials` is permitted by default.

The exact path is in `$CREDENTIALS_DIRECTORY`, so for a service whose name
may change:

```json
{"database": {"password": {"env": "CREDENTIALS_DIRECTORY"}}}
```

...or read the directory at startup and build the path.

## Serverless (Vercel, Lambda, Cloud Run)

Environment variables, set in the platform's dashboard or configuration:

```json
{"database": {"password": {"env": "DATABASE_PASSWORD"}}}
```

**Policy needed: none.**

A note on caching: a serverless filesystem is usually read-only and a cold
start discards process memory, so resolution caching helps only across
requests on the same warm instance. For `env` references there is nothing to
cache anyway — see [caching](caching.md).

## A password manager (1Password, Vault, AWS)

The one case that needs a policy, because a config that can name a command
can name any command.

```python
# app/startup.py
from secretref import CommandPolicy

CommandPolicy().allow("op", timeout_seconds=5)
```

```json
{"database": {"password": {"command": "op read op://prod/db/password"}}}
```

```python
CommandPolicy().allow("vault")
```

```json
{"database": {"password": {"command": "vault kv get -field=password secret/db"}}}
```

```python
CommandPolicy().allow("aws")
```

```json
{
  "database": {
    "password": {
      "command": "aws secretsmanager get-secret-value --secret-id prod/db --query SecretString --output text"
    }
  }
}
```

**Policy needed: one line.** Enable caching too — each resolution is a
subprocess, and for a cloud secret store a network round trip.

```python
from secretref import ResolutionCache

ResolutionCache().enable(ttl_seconds=300)
```

### Giving the CLI what it needs

A command runs with only the environment the policy names:

```python
CommandPolicy().allow(
    "op",
    pass_environment=["HOME", "OP_SERVICE_ACCOUNT_TOKEN"],
)
```

Without this, `op` cannot find its own credentials. The restriction is the
point: a subprocess handed the parent's whole environment can read every
other secret the process holds.

## A laptop

A `./secrets/` directory under a normal umask is group-readable, so the
default policy refuses it. One line:

```python
FilePolicy().restrict("./secrets", require_private=False)
```

**Policy needed: one line.** Better than teaching yourself to call
`allow_anywhere()`, which then ships to production.

Or skip files locally and use a `.env` file with your usual loader, pointing
the config at environment variables. The config file does not change between
development and production — only where the values come from.

## Different configs per environment

```
config/
  base.json
  development.json
  production.json
```

```python
import os
from secretref import load

environment = os.environ.get("APP_ENV", "development")
config = load(f"config/{environment}.json")
```

secretref does not merge configs. If you need hierarchical merging, let
OmegaConf or Dynaconf do that and audit the result — see
[comparison](comparison.md).

## A deployment checklist

```bash
secretref policy     # what this environment permits
secretref show       # what the config expects
secretref audit      # anything it should not be holding
```

Then, in the application, at startup rather than per request:

```python
audit(config, resolve=True)   # every secret actually fetches
```
