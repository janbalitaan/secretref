"""Auditing a config you did not write runs none of its commands.

The audit is meant for a pull request, where the config is whatever the
branch contains. A `command` reference that resolved would run it — so the
audit reports it as unverified instead.

    python examples/03_auditing_is_safe.py
"""

import json
from pathlib import Path
import tempfile

from secretref import CommandPolicy, audit, load

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    marker = root / "the-command-ran"
    path = root / "config.json"
    path.write_text(json.dumps({"api_key": {"command": f"sh -c 'touch {marker}'"}}))

    # Even with the command permitted, auditing does not run it.
    CommandPolicy().allow("sh")

    print("audit(config):")
    for finding in audit(load(path)):
        print(f"  {finding}")
    print(f"  did the command run? {marker.exists()}")

    print("\naudit(config, resolve=True) — for a config that is yours:")
    audit(load(path), resolve=True)
    print(f"  did the command run? {marker.exists()}")

    CommandPolicy().forbid()
