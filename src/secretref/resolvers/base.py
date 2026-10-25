"""What every resolver has to provide.

One resolver per reference form, each in its own module. A reference knows
*what* it points at; a resolver knows how to go and get it. Keeping them
apart means adding a source is a new file rather than another branch in a
model, and each one can be tested against its own backend without
constructing a reference at all.

A Protocol rather than a base class, so a resolver is anything with the right
shape — including one a downstream project writes without importing from
here.
"""

from __future__ import annotations

from typing import Protocol


class Resolver(Protocol):
    """Reads the value a reference points at.

    `described` is the reference's safe description, passed in so a message
    can name what failed without the resolver having to know what a
    reference is — and without ever holding the value in a message.
    """

    def read(self, locator: str, described: str) -> str:
        """Return the value, or empty when the source holds nothing.

        Empty is not an error: whether a missing value matters depends on the
        reference's default and on whether it is required, which the
        reference decides. A source that is *forbidden* is different — that
        is a configuration mistake, so it raises.
        """
        ...
