"""JSON, and the fallback for a file with no recognized extension.

Named `json_parser` rather than `json`. Naming it `json` would work — Python
3 resolves `import json` absolutely, so the stdlib still wins — but ruff has
a rule against shadowing a standard-library module name, and a reader seeing
`import json` inside a file called `json.py` has to stop and work out which
one they are getting. Five characters is a cheap way to never ask that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from secretref.exceptions import ConfigError
from secretref.parsers.base import Parser


class JsonParser(Parser):
    """JSON config files.

    Also the default, because a file with an unfamiliar extension is far more
    often JSON than anything else — and because failing with "not valid JSON"
    says more than "unknown format" does.
    """

    extensions: ClassVar[tuple[str, ...]] = (".json",)
    name: ClassVar[str] = "JSON"
    container: ClassVar[str] = "an object"

    @classmethod
    def parse(cls, text: str, path: Path | None) -> dict:
        """Parse JSON."""
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as error:
            raise ConfigError(f"{cls.describe(path)} is not valid JSON: {error}") from error
        return cls._require_mapping(parsed, path)
