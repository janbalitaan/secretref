"""Every constant the documentation claims is adjustable, actually is.

The table in `docs/extending.md` is a promise: a developer reads it instead
of reading the source, and a wrong row sends them looking for a parameter
that does not exist. Two rows were wrong when the table was first written —
they named the settings *field* rather than the `allow()` parameter — so the
table is checked rather than trusted.
"""

from __future__ import annotations

import inspect
from pathlib import Path
import re

import pytest

from secretref import (
    CommandPolicy,
    Config,
    EnvironmentPolicy,
    FilePolicy,
    Rules,
    constants,
    load,
    patterns,
)
from secretref.utils.repository import Repository

TABLE = Path(__file__).resolve().parents[2] / "docs" / "extending.md"


class TestTheConstantsTableIsTrue:
    """Each row names a real parameter or method, callable as written."""

    @staticmethod
    def _rows() -> list[tuple[str, str]]:
        """Pull the constant-to-override rows out of the documentation."""
        text = TABLE.read_text()
        section = text.split("## Every constant, and where to change it")[1]
        section = section.split("##")[0]
        rows = re.findall(r"^\| `([A-Z_]+)` \| (.+?) \|$", section, re.M)
        assert rows, "the constants table should have rows"
        return rows

    def test_the_table_is_not_empty(self):
        assert len(self._rows()) >= 12

    def test_every_constant_in_the_table_exists(self):
        """In `constants` or in `patterns` — the table spans both."""
        for name, _ in self._rows():
            assert hasattr(constants, name) or hasattr(patterns, name), (
                f"the table names a {name} that is in neither module"
            )

    def test_every_named_parameter_exists(self):
        """`Thing.method(parameter=...)` has to be callable as written."""
        owners = {
            "Rules": Rules,
            "Repository": Repository,
            "Config": Config,
            "CommandPolicy": CommandPolicy,
            "FilePolicy": FilePolicy,
            "EnvironmentPolicy": EnvironmentPolicy,
            "load": None,
        }
        for constant, where in self._rows():
            for owner, method, parameter in re.findall(
                r"`(\w+)\.(\w+)\((\w+)=\.\.\.\)`", where
            ):
                assert owner in owners, f"{constant}: unknown owner {owner}"
                attribute = getattr(owners[owner], method, None)
                assert attribute is not None, f"{constant}: no {owner}.{method}"
                assert parameter in inspect.signature(attribute).parameters, (
                    f"{constant}: {owner}.{method} has no {parameter} parameter"
                )

    def test_every_named_method_exists(self):
        """A bare `Rules.with_x` reference has to be a real method."""
        for constant, where in self._rows():
            for method in re.findall(r"`Rules\.(with_\w+)`", where):
                assert hasattr(Rules, method), f"{constant}: no Rules.{method}"

    def test_every_bare_parameter_exists(self):
        """`load(names=...)` — a module-level function with a parameter."""
        for constant, where in self._rows():
            for parameter in re.findall(r"`load\((\w+)=\.\.\.\)`", where):
                assert parameter in inspect.signature(load).parameters, (
                    f"{constant}: load has no {parameter} parameter"
                )

    @pytest.mark.parametrize(
        "name",
        [
            "KNOWN_SECRET_FORMATS",
            "SECRET_KEY",
            "PLACEHOLDERS",
            "MIN_SECRET_LENGTH",
            "REPOSITORY_MARKERS",
        ],
    )
    def test_the_rules_defaults_come_from_the_constants(self, name):
        """A `Rules()` with no arguments behaves exactly as the constants do,
        so adopting it changes nothing until a caller asks for a change."""
        source = patterns if hasattr(patterns, name) else constants
        expected = getattr(source, name)
        field = {
            "KNOWN_SECRET_FORMATS": "formats",
            "SECRET_KEY": "secret_key",
            "PLACEHOLDERS": "placeholders",
            "MIN_SECRET_LENGTH": "min_secret_length",
            "REPOSITORY_MARKERS": "repository_markers",
        }[name]
        assert getattr(Rules.default(), field) == expected
