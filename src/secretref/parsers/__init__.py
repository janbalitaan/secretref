"""One parser per config format, and the registry that picks between them.

One class per file, as in `models/` and `exceptions/`, so adding a format is
a new file plus one line in `PARSERS` rather than another branch in a
function that already handles two.

Not under `utils/`, despite being helpers. The test for belonging there is
whether something would make sense in an unrelated project, and a parser that
raises `ConfigError` would not — it is domain logic in a helper's clothes.
"""

from __future__ import annotations

from pathlib import Path

from secretref.parsers.base import Parser
from secretref.parsers.json_parser import JsonParser
from secretref.parsers.yaml_parser import YamlParser

__all__ = ["PARSERS", "JsonParser", "Parser", "YamlParser", "parser_for"]

# Tried in order. JsonParser is last because it is also the fallback for a
# file whose extension nothing recognizes.
PARSERS: tuple[type[Parser], ...] = (YamlParser, JsonParser)


def parser_for(path: Path | None) -> type[Parser]:
    """Pick the parser for a file, defaulting to JSON."""
    return next((parser for parser in PARSERS if parser.handles(path)), JsonParser)
