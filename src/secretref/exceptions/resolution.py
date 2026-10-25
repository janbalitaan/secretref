"""A reference that cannot be resolved."""

from __future__ import annotations

from secretref.exceptions.base import SecretrefError


class ResolutionError(SecretrefError, RuntimeError):
    """A reference could not be resolved to a value.

    A RuntimeError rather than a ValueError, because the reference itself is
    usually fine — the environment it names is not. That distinction is the
    useful part for a caller: a ConfigError means fix the file, a
    ResolutionError means fix the deployment.

    Carries the reference's description rather than its value, so the message
    is safe to log and safe to show a user.
    """
