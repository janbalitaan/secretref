"""Returning a value that is already here."""

from __future__ import annotations


class LiteralResolver:
    """Returns the value as given.

    Nothing to fetch and no policy to ask: the point of the literal form is
    that the value is inline, which is why `audit` reports every one of them.
    """

    def read(self, locator: str, described: str) -> str:  # noqa: ARG002
        """Return the locator, which is the value itself.

        `described` goes unused: there is no failure to report when the
        value is already in hand. The argument stays so this matches the
        Resolver protocol.
        """
        return locator
