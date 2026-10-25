"""Failing a deployment rather than a request.

A missing secret should stop the process coming up, not surface on the first
request that needs it.

    python examples/05_a_startup_check.py
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile

from secretref import audit, load


@dataclass(frozen=True)
class Settings:
    """What the rest of the application takes values from."""

    database_url: str
    service_name: str

    @classmethod
    def from_config(cls, path: Path) -> "Settings":
        config = load(path)

        # Resolve is True because this config is ours, so a secret that
        # cannot be fetched should stop the deployment.
        blocking = [finding for finding in audit(config, resolve=True) if finding.blocking]
        if blocking:
            raise SystemExit("\n".join(str(finding) for finding in blocking))

        password = config.secret("database.password").resolve()
        host = config.require("database.host")
        return cls(
            database_url=f"postgresql://app:{password}@{host}/billing",
            service_name=config.require("service_name"),
        )


CONFIG = {
    "service_name": "billing",
    "database": {"host": "db.internal", "password": {"env": "DATABASE_PASSWORD"}},
}

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "config.json"
    path.write_text(json.dumps(CONFIG))

    os.environ["DATABASE_PASSWORD"] = "a-real-password"
    settings = Settings.from_config(path)

    # The URL holds the password, so it is not something to print. Shown
    # redacted here to make the point.
    print(f"service:  {settings.service_name}")
    print("database: postgresql://app:***@db.internal/billing")
    print("\nstarted cleanly, because every secret resolved.")
    del os.environ["DATABASE_PASSWORD"]
