"""Config files that name their secrets instead of containing them.

An `.env` file works until the config needs a list, a nested section, or a
number that is really a number. JSON and YAML handle all three — but then the
secrets are sitting in a file next to the code, which is how they end up in a
repository.

So a secret in a config file here is a *reference*:

    {
      "providers": [
        {"name": "openai",    "api_key": {"env": "OPENAI_API_KEY"}},
        {"name": "anthropic", "api_key": {"file": "/run/secrets/anthropic"}},
        {"name": "internal",  "api_key": {"command": "op read op://vault/key"}}
      ],
      "timeout_seconds": 30,
      "languages": ["en", "fil"]
    }

The file is committable, because it says where each secret lives rather than
what it is. Resolution is lazy, so a config naming twenty secrets reads none
of them at load — which is what lets one file serve development and
production.

    from secretref import load

    config = load("config.json")
    key = config.secret("providers.0.api_key").resolve()

And the part that makes it worth a library rather than a helper function:

    from secretref import audit

    for finding in audit(config):
        print(finding)
    # error: providers.0.api_key: a literal secret inside a repository
    #   try: move it to an environment variable and reference it

`audit` reports a literal secret as an **error** when it finds a repository
above the file, because such a value is one commit from a remote. Outside a
repository the same value is a warning. That check is the reason this exists:
the failure it prevents is not a crash but a leak, which no test catches.

No dependencies. A library that reads your secrets should be auditable in an
afternoon.
"""

from secretref.auditors import audit, repository_root
from secretref.cache import ResolutionCache
from secretref.constants import REDACTED
from secretref.exceptions import (
    CommandNotAllowedError,
    ConfigError,
    FileNotAllowedError,
    ResolutionError,
    SecretrefError,
    VariableNotAllowedError,
)
from secretref.models import (
    Config,
    Finding,
    Rules,
    SecretRef,
    Severity,
    Source,
)
from secretref.policies import CommandPolicy, EnvironmentPolicy, FilePolicy

__all__ = [
    "REDACTED",
    "CommandNotAllowedError",
    "CommandPolicy",
    "Config",
    "ConfigError",
    "EnvironmentPolicy",
    "FileNotAllowedError",
    "FilePolicy",
    "Finding",
    "ResolutionCache",
    "ResolutionError",
    "Rules",
    "SecretRef",
    "SecretrefError",
    "Severity",
    "Source",
    "VariableNotAllowedError",
    "__version__",
    "audit",
    "find_config",
    "load",
    "loads",
    "repository_root",
]
__version__ = "0.1.1"

# The public API stays functions, because `load("config.json")` is what a
# caller wants to write. Config holds the implementation, so the pieces live
# with the type they build rather than in a module of their own.
load = Config.load
loads = Config.loads
find_config = Config.find
