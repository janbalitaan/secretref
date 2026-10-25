"""A config file that names its secrets instead of containing them.

python examples/01_reading_a_config.py
"""

import json
from pathlib import Path
import tempfile

from secretref import SecretrefError, load

CONFIG = {
    "service_name": "billing",
    "database": {
        "host": "db.internal",
        "port": 5432,
        "password": {"env": "DATABASE_PASSWORD"},
    },
    "smtp_password": {"env": "SMTP_PASSWORD", "required": False},
    "region": {"env": "AWS_REGION", "default": "us-east-1"},
}

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "config.json"
    path.write_text(json.dumps(CONFIG, indent=2))

    config = load(path)

    # Plain values come back as they are.
    print(f"host:    {config.get('database.host')}")
    print(f"port:    {config.get('database.port')}")
    print(f"missing: {config.get('nothing.here', 'a fallback')}")

    # A secret needs one more step, so reading one is always visible in the
    # code rather than looking like any other lookup.
    reference = config.secret("database.password")
    print(f"\nreference:  {reference.described()}")

    # Required and missing raises, which is the point: a deployment that
    # forgot to set it should fail now rather than on the first request that
    # needs it.
    try:
        reference.resolve()
    except SecretrefError as error:
        print(f"required:   raises — {error}")

    # Optional and missing is empty, for a feature that is simply off.
    print(f"optional:   {config.secret('smtp_password').resolve()!r}")

    # A default is for configuration, not for a secret.
    print(f"default:    {config.secret('region').resolve()}")

    print("\nevery reference this config expects:")
    for dotted, secret in sorted(config.secrets().items()):
        optional = "" if secret.required else "  (optional)"
        print(f"  {dotted:16} {secret.described()}{optional}")
