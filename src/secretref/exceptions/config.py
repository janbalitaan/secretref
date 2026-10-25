"""A config file that cannot be used."""

from __future__ import annotations

from secretref.exceptions.base import SecretrefError


class ConfigError(SecretrefError, ValueError):
    """A config file cannot be read, or a path is not in it.

    A ValueError too, because that is what a malformed config has always
    been: the file was found, and its contents are wrong.
    """
