"""An environment reference that policy will not read."""

from __future__ import annotations

from secretref.exceptions.base import SecretrefError


class VariableNotAllowedError(SecretrefError, PermissionError):
    """An environment reference named a variable it may not read.

    The reason this can matter even though the process already holds the
    variable: a config that can be edited can repoint a field the
    application *displays* at a variable it should not. The attacker gains
    no access to the environment — they redirect an existing data flow to
    carry something out of it.
    """
