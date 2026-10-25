"""Reading a secret from the environment."""

from __future__ import annotations

import os

from secretref.policies.environment import EnvironmentPolicy


class EnvironmentResolver:
    """Reads an environment variable, if the policy permits that one.

    The cheapest source and the default for most deployments: a platform
    that injects secrets as environment variables needs no policy setup at
    all.
    """

    def read(self, locator: str, described: str) -> str:
        """Return the variable's value, or empty when it is not set."""
        EnvironmentPolicy().check(locator, described)
        return os.environ.get(locator, "").strip()
