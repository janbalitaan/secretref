"""YAML, through the optional `yaml` extra.

Named `yaml_parser` rather than `yaml`, for the same reason as
`json_parser`: a file called `yaml.py` that imports `yaml` reads like a
mistake even when it is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from secretref.exceptions import ConfigError
from secretref.parsers.base import Parser


class YamlParser(Parser):
    """YAML config files, when PyYAML is installed."""

    extensions: ClassVar[tuple[str, ...]] = (".yaml", ".yml")
    name: ClassVar[str] = "YAML"
    container: ClassVar[str] = "a mapping"

    @classmethod
    def parse(cls, text: str, path: Path | None) -> dict:
        """Parse YAML, if PyYAML is installed.

        `safe_load`, never `load`. A config file is often less trusted than
        the code reading it, and `load` will construct arbitrary Python
        objects from a tag in the document — including ones that run.
        """
        try:
            import yaml  # noqa: PLC0415 - an optional extra, absent by default
        except ImportError as error:
            raise ConfigError(
                f"{path} is YAML, which needs the yaml extra: pip install 'secretref[yaml]'"
            ) from error
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise ConfigError(f"{cls.describe(path)} is not valid YAML: {error}") from error
        return cls._require_mapping(parsed, path)
