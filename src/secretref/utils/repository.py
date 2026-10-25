"""Finding the working copy a file sits in."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from secretref.constants import MAX_PARENTS_SEARCHED, REPOSITORY_MARKERS
from secretref.exceptions import ConfigError


class Repository:
    """Locating a version control working copy.

    Why a library about secrets cares: a literal secret inside a working copy
    is one commit from a remote, and git history keeps it after the fix. The
    same value outside one is careless but contained. That is the whole basis
    for the audit's severity, so it gets its own named helper rather than an
    inline check.
    """

    # A subclass can set these once rather than passing them at every call
    # site. Both are also per-call arguments, for a caller who needs a
    # different answer in one place — a repository marker this version does
    # not know should not mean waiting for a release.
    MARKERS: ClassVar[tuple[str, ...]] = REPOSITORY_MARKERS
    MAX_PARENTS: ClassVar[int] = MAX_PARENTS_SEARCHED

    @classmethod
    def root(
        cls,
        start: Path | str,
        markers: Sequence[str] | None = None,
        max_parents: int | None = None,
    ) -> Path | None:
        """Find the working copy containing `start`, or None when there is none.

        Walks upward looking for a marker. Bounded, because an unusual mount
        can make the walk long and the answer is not worth an unbounded
        search. A `.git` file counts as well as a directory, since a worktree
        or submodule has one.

        `markers` names what counts as a working copy root, for a version
        control system this version does not list — `.jj`, `.fossil`, `.bzr`.
        Getting it wrong costs real accuracy: a literal secret inside an
        unrecognized repository is reported as merely careless when it is
        actually one commit from a remote.
        """
        limit = cls.MAX_PARENTS if max_parents is None else max_parents
        if limit < 1:
            raise ConfigError(
                f"max_parents must be at least 1 (got {limit}); "
                "0 would not even check the starting directory"
            )
        current = Path(start).resolve()
        if current.is_file():
            current = current.parent
        for _ in range(limit):
            if cls.contains_marker(current, markers):
                return current
            if current.parent == current:
                return None
            current = current.parent
        return None

    @classmethod
    def contains_marker(cls, directory: Path, markers: Sequence[str] | None = None) -> bool:
        """Whether this directory is the root of a working copy."""
        chosen = cls.MARKERS if markers is None else markers
        return any((directory / marker).exists() for marker in chosen)
