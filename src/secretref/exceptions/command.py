"""A command reference that policy will not run."""

from __future__ import annotations

from secretref.exceptions.base import SecretrefError


class CommandNotAllowedError(SecretrefError, PermissionError):
    """A command reference was refused before it ran.

    Separate from `ResolutionError` because it means something different. A
    ResolutionError says the secret was not where the config said it would
    be; this says the config asked to run something it is not permitted to
    run, and no amount of fixing the environment will change that.

    A PermissionError too, so `except PermissionError` catches it alongside
    the filesystem refusals a caller already handles.
    """
