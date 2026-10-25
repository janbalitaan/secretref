"""Auditing for a credential format this version has never heard of.

The shipped rules cover eighteen published formats and the usual credential
key names. They cannot cover a vendor released last month, or one team's
convention. So they are data rather than constants.

    python examples/06_extending.py
"""

import json
from pathlib import Path
import re
import subprocess
import tempfile

from secretref import Rules, audit, load
from secretref.constants import REPOSITORY_MARKERS

CONFIG = {
    "fastly": {"token": "fsk_live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"},
    "access_pass": "s0mething-that-looks-like-a-real-secret",
    "database": {"password": "__REPLACE_ME__"},
}

# This codebase's conventions, in one place, as code.
RULES = (
    Rules.default()
    # A vendor the shipped list does not cover. Anchored on the published
    # prefix: a pattern loose enough to match any 32-character string would
    # label every other secret in the file a Fastly token.
    .with_formats({"a Fastly API token": re.compile(r"\bfsk_live_[A-Za-z0-9]{24}\b")})
    # This team's name for a credential.
    .with_secret_keys(["access_pass"])
    # This team's "not filled in yet" marker.
    .with_placeholders([r"^__[A-Z_]+__$"])
    # Jujutsu working copies count as repositories too.
    .with_repository_markers((*REPOSITORY_MARKERS, ".jj"))
)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    path = root / "config.json"
    path.write_text(json.dumps(CONFIG, indent=2))
    config = load(path)

    print("with the shipped rules:")
    shipped = audit(config)
    for finding in shipped:
        print(f"  {str(finding).splitlines()[0]}")
    if not shipped:
        print("  nothing — none of these match what it knows about")

    print(f"\n{RULES.describe()}")
    print("with this codebase's rules:")
    for finding in audit(config, rules=RULES):
        print(f"  {str(finding).splitlines()[0]}")

print("\na typo is refused rather than silently ignored:")
try:
    Rules.default().with_formats(without=("a Stipe secret key",))
except Exception as error:
    print(f"  {str(error).split('.')[0]}")
