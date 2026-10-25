"""What a file policy permits.

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

from dataclasses import dataclass, replace
from pathlib import Path

from secretref.constants import (
    MAX_SECRET_FILE_BYTES,
    SECRET_MOUNTS,
)


@dataclass(frozen=True, slots=True)
class FileSettings:
    """Where a file reference may read from.

    Starts confined to the conventional mounts rather than anywhere, because
    a config that can be edited could otherwise name any readable path.
    """

    roots: tuple[Path, ...] = tuple(Path(root) for root in SECRET_MOUNTS)
    require_private: bool = False
    max_bytes: int = MAX_SECRET_FILE_BYTES

    def with_changes(self, **changes: object) -> FileSettings:
        """Build the next snapshot, replacing some fields."""
        return replace(self, **changes)  # type: ignore[arg-type]
