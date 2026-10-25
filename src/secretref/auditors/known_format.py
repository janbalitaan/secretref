"""Whether a value is a credential whose issuer publishes its shape."""

from __future__ import annotations

import re
from typing import ClassVar

from secretref.patterns import KNOWN_SECRET_FORMATS


class KnownFormat:
    """Whether a value matches a published credential format.

    The one kind of secret that can be identified from the value alone. Every
    other check in this package starts from the key name, which is the thing
    an audit cannot depend on: a live Stripe key under `payments.api_key` is
    found either way, while the same key under `tracking.ref` is found only
    here.

    A match is reported as an error regardless of the key, and regardless of
    whether the config is inside a repository — a key matching a published
    format is a real credential, not a placeholder someone typed.
    """

    FORMATS: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = KNOWN_SECRET_FORMATS

    @classmethod
    def identify(cls, value: str) -> str:
        """Name the credential format this value matches, or return empty.

        The first match wins. The patterns are specific enough that two
        matching the same value would mean one of them is wrong.
        """
        for name, pattern in cls.FORMATS:
            if pattern.search(value):
                return name
        return ""

    @classmethod
    def matches(cls, value: str) -> bool:
        """Whether this value matches any published credential format."""
        return bool(cls.identify(value))
