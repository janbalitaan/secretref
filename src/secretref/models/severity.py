"""How much a finding matters."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum


class Severity(Enum):
    """How much a finding matters.

    The distinction is whether the value could already have been published.
    A literal secret inside a working copy is one commit from a remote, so it
    is an ERROR. A literal outside one is a WARNING: careless, but contained.
    """

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"

    @property
    def rank(self) -> int:
        """Where this sits, most severe first.

        An explicit rank rather than relying on declaration order, because
        the order of an Enum's members is not something a reader should have
        to depend on — and inserting a severity between two existing ones
        would silently change every comparison.
        """
        return _RANKS[self]

    def __lt__(self, other: object) -> bool:
        """Order by severity, so `sorted` and `max` mean what they look like.

        Defined rather than inherited from IntEnum: the values are the
        strings that appear in output, and making them integers would put
        the wire format at the mercy of the ordering.
        """
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def worst(cls, severities: Iterable[Severity]) -> Severity | None:
        """Return the most severe of several, or None when there are none.

        What a caller wants after an audit: one answer about whether to
        proceed, rather than a list to reduce themselves.
        """
        return min(severities, default=None)


# Lower is more severe, so `min` is the worst and `sorted` reads in the order
# a reader wants: the things to fix first, first.
_RANKS = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.NOTE: 2}
