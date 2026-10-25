"""What a command policy permits.

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
from pathlib import Path

from secretref.constants import (
    COMMAND_TIMEOUT_SECONDS,
    MAX_COMMAND_OUTPUT_BYTES,
    MINIMAL_ENVIRONMENT,
)


@dataclass(frozen=True, slots=True)
class CommandSettings:
    """What a command reference may do. The safe position is the default."""

    enabled: bool = False
    allowed: frozenset[str] = field(default_factory=frozenset)
    # The absolute paths those names resolved to when the policy was
    # configured. Pinning them is what stops a later PATH change from
    # substituting a different file for an allowed name.
    resolved: frozenset[str] = field(default_factory=frozenset)
    require_absolute: bool = False
    timeout: float = COMMAND_TIMEOUT_SECONDS
    max_output: int = MAX_COMMAND_OUTPUT_BYTES
    passthrough: tuple[str, ...] = MINIMAL_ENVIRONMENT
    working_directory: Path | None = None

    def with_changes(self, **changes: object) -> CommandSettings:
        """Build the next snapshot, replacing some fields."""
        return replace(self, **changes)  # type: ignore[arg-type]
