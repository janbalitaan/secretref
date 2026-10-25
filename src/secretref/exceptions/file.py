"""A file reference that policy will not read."""

from __future__ import annotations

from secretref.exceptions.base import SecretrefError


class FileNotAllowedError(SecretrefError, PermissionError):
    """A file reference was refused before it was read.

    Separate from `ResolutionError` for the same reason
    `CommandNotAllowedError` is: that one means the secret was not where the
    config said it would be, while this means the config asked to read
    somewhere it is not permitted to read, and fixing the environment will
    not change that.
    """
