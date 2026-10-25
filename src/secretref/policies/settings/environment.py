"""What an environment policy permits.

A policy is read on every resolution and written when an operator
configures it. Those two happening at once is the problem: assigning several
fields in sequence means a reader between the first and the last sees a
configuration nobody asked for — and in the worst ordering, a more permissive
one than either the old or the new.

Locking the reads would work and would put a lock on the hot path. Instead the
policy keeps one of these, frozen, and swaps the whole object in a single
assignment. Attribute assignment is atomic in CPython, so a reader sees the
old snapshot or the new one and never a mixture. Reads need no lock at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import re


@dataclass(frozen=True, slots=True)
class EnvironmentSettings:
    """Which variables a reference may name.

    `active` is separate from whether there are any rules, because
    "restricted to nothing" and "not restricted" are different states —
    the first is how environment references are switched off.
    """

    active: bool = False
    names: frozenset[str] = field(default_factory=frozenset)
    prefixes: tuple[str, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()

    def with_changes(self, **changes: object) -> EnvironmentSettings:
        """Build the next snapshot, replacing some fields."""
        return replace(self, **changes)  # type: ignore[arg-type]
