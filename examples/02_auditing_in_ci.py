"""The audit, which is what this library is for.

One line in a pipeline, and a non-zero exit when a config holds something it
should only be pointing at.

    python examples/02_auditing_in_ci.py
"""

import json
from pathlib import Path
import subprocess
import tempfile

from secretref import audit, load

CARELESS = {
    "payments": {
        # A real credential, inline. Detected by its published format.
        "stripe_key": "sk_live_" + "0" * 24,
        # Also inline, but no published shape — caught by the key name.
        "webhook_secret": "j4K9mQ2xR7vN8pL3wT6yB1zF5h",
    },
    "tracking": {
        # Nothing about this key name suggests a credential, which is why
        # detection cannot rely on key names alone.
        "ref": "AKIAIOSFODNN7EXAMPLE",
    },
    "database": {"password": {"env": "DATABASE_PASSWORD"}},
}

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    path = root / "config.json"
    path.write_text(json.dumps(CARELESS, indent=2))

    for finding in audit(load(path)):
        print(finding)

    blocking = [f for f in audit(load(path)) if f.blocking]
    print(f"\n{len(blocking)} blocking findings -> exit 1")

print("""
In a pipeline that is one line:

    - run: pip install secretref
    - run: secretref audit --strict
""")
