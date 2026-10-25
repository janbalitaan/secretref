"""Finding the working copy a file sits in."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from secretref.constants import MAX_PARENTS_SEARCHED, REPOSITORY_MARKERS


class Repository:
    """Locating a version control working copy.

    Why a library about secrets cares: a literal secret inside a working copy
    is one commit from a remote, and git history keeps it after the fix. The
    same value outside one is careless but contained. That is the whole basis
    for the audit's severity, so it gets its own named helper rather than an
    inline check.
    """

    MARKERS: ClassVar[tuple[str, ...]] = REPOSITORY_MARKERS

    @classmethod
    def root(cls, start: Path | str) -> Path | None:
        """Find the working copy containing `start`, or None when there is none.

        Walks upward looking for a marker. Bounded, because an unusual mount
        can make the walk long and the answer is not worth an unbounded
        search. A `.git` file counts as well as a directory, since a worktree
        or submodule has one.
        """
        current = Path(start).resolve()
        if current.is_file():
            current = current.parent
        for _ in range(MAX_PARENTS_SEARCHED):
            if cls.contains_marker(current):
                return current
            if current.parent == current:
                return None
            current = current.parent
        return None

    @classmethod
    def contains_marker(cls, directory: Path) -> bool:
        """Whether this directory is the root of a working copy."""
        return any((directory / marker).exists() for marker in cls.MARKERS)
