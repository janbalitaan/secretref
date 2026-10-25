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
    def identify(
        cls,
        value: str,
        formats: tuple[tuple[str, re.Pattern[str]], ...] | None = None,
    ) -> str:
        """Name the credential format this value matches, or return empty.

        The first match wins, which is why the order places narrower
        patterns before wider ones. `formats` overrides the shipped list, for
        a caller who has added a vendor or corrected one — see
        `secretref.models.rules`.
        """
        for name, pattern in formats if formats is not None else cls.FORMATS:
            if pattern.search(value):
                return name
        return ""

    @classmethod
    def matches(
        cls,
        value: str,
        formats: tuple[tuple[str, re.Pattern[str]], ...] | None = None,
    ) -> bool:
        """Whether this value matches any published credential format."""
        return bool(cls.identify(value, formats))
