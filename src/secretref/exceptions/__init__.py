"""Everything this library raises.

One file per class, as in `models/`, so a new exception is a new file rather
than an edit to a shared one. The tree, for deciding what to catch:

    SecretrefError                  everything below
      ConfigError                   the file is wrong — fix the config
      ResolutionError               the environment is wrong — fix the deploy
      CommandNotAllowedError        policy refused to run it — fix the policy
      FileNotAllowedError           policy refused to read it — fix the policy
      VariableNotAllowedError       policy refused the variable — fix the policy

That split is the one worth knowing. A ConfigError means a human mistyped
something and the fix is in the repository. A ResolutionError means the
config is right and the secret is not where it said it would be, so the fix
is in the deployment.

Each leaf also inherits from the built-in it replaces, so `except ValueError`
and `except RuntimeError` keep working for a caller who has not adopted these.
"""

from secretref.exceptions.base import SecretrefError
from secretref.exceptions.command import CommandNotAllowedError
from secretref.exceptions.config import ConfigError
from secretref.exceptions.environment import VariableNotAllowedError
from secretref.exceptions.file import FileNotAllowedError
from secretref.exceptions.resolution import ResolutionError

__all__ = [
    "CommandNotAllowedError",
    "ConfigError",
    "FileNotAllowedError",
    "ResolutionError",
    "SecretrefError",
    "VariableNotAllowedError",
]
