"""Branches of the audit that depend on how a literal looks.

An explicit `{"literal": ...}` mapping and a plain string reach the same
check by different routes, and a placeholder has to come back as a note
rather than an error however it arrived.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from secretref import ResolutionError, SecretRef, Severity, Source, audit, load


@pytest.fixture
def repository(tmp_path):
    """A directory that is a working copy, where literals are errors."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def write(directory, data):
    """Put a config in a directory and load it."""
    path = directory / "config.json"
    path.write_text(json.dumps(data))
    return load(path)


class TestNoisyLiterals:
    def test_an_explicit_literal_mapping_is_audited(self, repository):
        """`{"literal": ...}` is found by secrets(), not by the string walk,
        so it reaches the check down a different path."""
        config = write(repository, {"api_key": {"literal": "sk-live-abcdef1234567890"}})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.ERROR

    def test_an_explicit_literal_placeholder_is_only_a_note(self, repository):
        config = write(repository, {"api_key": {"literal": "your-api-key-here"}})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.NOTE
        assert "placeholder" in findings[0].message

    def test_a_short_explicit_literal_is_only_a_note(self, repository):
        """Too short to judge, so reporting it as an error would be noise."""
        config = write(repository, {"api_key": {"literal": "abc"}})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.NOTE

    def test_the_note_says_what_to_do(self, repository):
        config = write(repository, {"api_key": {"literal": "changeme"}})
        assert "before deploying" in audit(config)[0].remedy

    def test_an_explicit_literal_resolves_to_its_value(self):
        """The form exists so a caller can be explicit that a value is
        inline rather than a reference someone forgot to finish."""
        assert SecretRef.parse({"literal": "inline"}).resolve() == "inline"

    def test_an_already_parsed_reference_passes_through(self):
        """parse() is idempotent, so a caller can hand it either form."""
        original = SecretRef.parse({"env": "X"})
        assert SecretRef.parse(original) is original

    def test_none_becomes_an_empty_literal(self):
        """A null in a config parses, and then refuses to resolve.

        Parsing has to accept it — the file contains something — but an
        empty required value is exactly what `resolve` exists to catch.
        """
        reference = SecretRef.parse(None)
        assert reference.source is Source.LITERAL
        with pytest.raises(ResolutionError, match="resolves to nothing"):
            reference.resolve()

    def test_a_number_becomes_a_literal(self):
        """JSON allows a number where a string was meant; coercing it keeps
        the audit able to look at it."""
        assert SecretRef.parse(12345678).resolve() == "12345678"
