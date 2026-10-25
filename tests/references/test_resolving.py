"""Reading the value a reference points at."""

from __future__ import annotations

import pytest

from secretref import CommandNotAllowedError, ResolutionError, SecretRef, Source


class TestResolving:
    def test_an_environment_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "sk-from-env")
        assert SecretRef.parse({"env": "TEST_KEY"}).resolve() == "sk-from-env"

    def test_surrounding_whitespace_is_stripped(self, monkeypatch):
        """A secret pasted into a variable or a file usually brings a newline."""
        monkeypatch.setenv("TEST_KEY", "  sk-padded\n")
        assert SecretRef.parse({"env": "TEST_KEY"}).resolve() == "sk-padded"

    def test_a_file(self, tmp_path, files_anywhere):
        secret = tmp_path / "key"
        secret.write_text("sk-from-file\n")
        assert SecretRef.parse({"file": str(secret)}).resolve() == "sk-from-file"

    def test_a_command(self, commands_allowed):
        reference = SecretRef.parse({"command": "echo sk-from-command"})
        assert reference.resolve() == "sk-from-command"

    def test_a_literal(self):
        assert SecretRef.parse("sk-inline").resolve() == "sk-inline"

    def test_a_default_is_used_when_absent(self):
        reference = SecretRef.parse({"env": "DEFINITELY_NOT_SET", "default": "fallback"})
        assert reference.resolve() == "fallback"

    def test_an_optional_reference_returns_empty(self):
        reference = SecretRef.parse({"env": "DEFINITELY_NOT_SET", "required": False})
        assert reference.resolve() == ""

    def test_a_required_reference_raises(self):
        with pytest.raises(ResolutionError, match="resolves to nothing"):
            SecretRef.parse({"env": "DEFINITELY_NOT_SET"}).resolve()

    def test_a_missing_file_is_not_a_crash(self, tmp_path, files_anywhere):
        """resolve decides what absent means; reading does not."""
        reference = SecretRef.parse({"file": str(tmp_path / "nope"), "required": False})
        assert reference.resolve() == ""

    def test_a_literal_can_be_refused(self):
        """How a caller enforces the audit's finding in production."""
        with pytest.raises(ResolutionError, match="literal value"):
            SecretRef.parse("sk-inline").resolve(allow_literal=False)

    def test_a_reference_is_unaffected_by_that_flag(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "sk-fine")
        assert SecretRef.parse({"env": "TEST_KEY"}).resolve(allow_literal=False) == "sk-fine"

    def test_is_resolvable_does_not_raise(self):
        assert SecretRef.parse({"env": "DEFINITELY_NOT_SET"}).is_resolvable() is False

    def test_a_failing_command_raises_without_its_output(self, commands_allowed):
        """A failing secret tool often prints the secret to stderr."""
        reference = SecretRef.parse({"command": "sh -c 'echo s3cret >&2; exit 3'"})
        with pytest.raises(ResolutionError) as caught:
            reference.resolve()
        assert "s3cret" not in str(caught.value)
        assert "status 3" in str(caught.value)

    def test_a_failing_command_raises_without_its_arguments(self, commands_allowed):
        """The command itself can hold a secret, so only the executable is
        named in the message."""
        reference = SecretRef.parse({"command": "sh -c 'exit 1' --token=s3cret"})
        with pytest.raises(ResolutionError) as caught:
            reference.resolve()
        assert "s3cret" not in str(caught.value)
        assert "'sh'" in str(caught.value)

    def test_a_command_cannot_chain(self, commands_allowed):
        """Split with shlex and run without a shell, so a semicolon is an
        argument rather than a separator: one echo, not two."""
        reference = SecretRef.parse({"command": "echo one; echo two"})
        assert reference.resolve() == "one; echo two"

    def test_an_empty_command_raises(self, commands_allowed):
        """The policy owns this, since deciding what may run is its job."""
        with pytest.raises(CommandNotAllowedError, match="empty command"):
            SecretRef.parse({"command": "   "}).resolve()

    def test_resolution_is_lazy(self, monkeypatch):
        """Parsing reads nothing, which is what lets one config serve
        several environments."""
        reference = SecretRef.parse({"env": "SET_LATER"})
        monkeypatch.setenv("SET_LATER", "sk-late")
        assert reference.resolve() == "sk-late"

    def test_the_source_is_recorded(self):
        assert SecretRef.parse({"env": "X"}).source is Source.ENV
        assert SecretRef.parse({"file": "/x"}).source is Source.FILE
        assert SecretRef.parse({"command": "x"}).source is Source.COMMAND
        assert SecretRef.parse("x").source is Source.LITERAL
