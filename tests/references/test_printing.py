"""Printing a reference must never print the secret.

A repr turns up in tracebacks, log lines, f-strings and pytest assertion
output — none of which anyone reviews before it is written down. The default
dataclass repr would have printed `locator`, which for a literal *is* the
secret, so these tests exist to keep that from coming back.
"""

from __future__ import annotations

import pytest

from secretref import SecretRef

SECRET = "sk-live-abcdef1234567890"


class TestPrinting:
    def test_a_literal_is_redacted_in_repr(self):
        assert repr(SecretRef.parse(SECRET)) == "SecretRef(source=literal, locator=<redacted>)"

    def test_a_literal_is_safe_in_str(self):
        assert str(SecretRef.parse(SECRET)) == "a literal value"

    @pytest.mark.parametrize("formatter", [repr, str, lambda ref: f"{ref}", "{}".format])
    def test_no_way_of_printing_reveals_it(self, formatter):
        assert SECRET not in formatter(SecretRef.parse(SECRET))

    def test_an_env_reference_names_its_variable(self):
        """Safe to show, and the only useful thing to say about it."""
        assert repr(SecretRef.parse({"env": "OPENAI_API_KEY"})) == (
            "SecretRef(source=env, locator='OPENAI_API_KEY')"
        )

    def test_a_file_reference_names_its_path(self):
        assert "/run/secrets/x" in repr(SecretRef.parse({"file": "/run/secrets/x"}))

    def test_a_command_shows_only_its_executable(self):
        """Arguments can hold a secret — `--token=...` is a real pattern."""
        ref = SecretRef.parse({"command": "op read op://vault/key --token=s3cret"})
        assert repr(ref) == "SecretRef(source=command, locator='op')"
        assert "s3cret" not in repr(ref)

    def test_an_unparseable_command_still_prints(self):
        """shlex raises on an unbalanced quote; the repr must not."""
        ref = SecretRef.parse({"command": 'op read "unclosed'})
        assert "op" in repr(ref)

    def test_an_empty_command_still_prints(self):
        assert "command" in repr(SecretRef.parse({"command": "   "}))

    def test_a_default_is_reported_without_its_value(self):
        """A default can itself be sensitive, so only its presence shows."""
        ref = SecretRef.parse({"env": "X", "default": "fallback-secret"})
        assert "default=<set>" in repr(ref)
        assert "fallback-secret" not in repr(ref)

    def test_optionality_is_reported(self):
        assert "required=False" in repr(SecretRef.parse({"env": "X", "required": False}))

    def test_a_plain_reference_reports_neither(self):
        rendered = repr(SecretRef.parse({"env": "X"}))
        assert "default" not in rendered
        assert "required" not in rendered

    def test_a_default_round_trips_through_parse(self):
        """Exercises the default-reading path with a value present."""
        assert SecretRef.parse({"env": "X", "default": "value"}).default == "value"

    def test_no_default_reads_as_none(self):
        assert SecretRef.parse({"env": "X"}).default is None
