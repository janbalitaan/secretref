"""The root of the hierarchy."""

from __future__ import annotations


class SecretrefError(Exception):
    """Base for everything this library raises.

    Catch this to handle any failure from secretref without catching
    unrelated errors from elsewhere.
    """
