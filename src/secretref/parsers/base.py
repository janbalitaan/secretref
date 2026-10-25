"""What every config format has to provide."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from secretref.constants import UNNAMED_CONFIG
from secretref.exceptions import ConfigError


class Parser(ABC):
    """One config format.

    `extensions` is what the registry matches on, so a parser declares what
    it handles rather than the loader keeping a separate list that can drift
    out of step with it.
    """

    extensions: ClassVar[tuple[str, ...]] = ()
    name: ClassVar[str] = "config"
    container: ClassVar[str] = "a mapping"

    @classmethod
    def describe(cls, path: Path | None) -> str:
        """Name a config in a message, whether or not it came from a file."""
        return str(path) if path else UNNAMED_CONFIG

    @classmethod
    def handles(cls, path: Path | None) -> bool:
        """Whether this parser is the one for that file."""
        return path is not None and path.suffix.lower() in cls.extensions

    @classmethod
    @abstractmethod
    def parse(cls, text: str, path: Path | None) -> dict:
        """Parse the text, raising ConfigError on anything unusable."""

    @classmethod
    def _require_mapping(cls, parsed: object, path: Path | None) -> dict:
        """Reject a document whose top level is not a mapping.

        A list at the top level parses fine and then fails confusingly later,
        when something asks for a key. Refusing here names the real problem
        while the filename is still in hand.
        """
        if not isinstance(parsed, dict):
            raise ConfigError(
                f"{cls.describe(path)} must contain {cls.container} at the top level"
            )
        return parsed
