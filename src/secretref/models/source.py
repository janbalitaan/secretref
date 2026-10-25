"""Where a secret comes from."""

from __future__ import annotations

from enum import Enum


class Source(Enum):
    """How a reference resolves to a value.

    LITERAL is included deliberately rather than forbidden outright. A
    literal is right for a local experiment and wrong in a repository, and
    the audit is what tells those apart — refusing it at parse time would
    make the library annoying enough to work around.
    """

    ENV = "env"
    FILE = "file"
    COMMAND = "command"
    LITERAL = "literal"
