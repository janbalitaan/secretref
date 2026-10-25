"""Saying what a secret is without saying what it holds."""

from __future__ import annotations

from secretref import REDACTED, SecretRef


class TestDescribing:
    def test_a_reference_names_its_source(self):
        assert SecretRef.parse({"env": "OPENAI_API_KEY"}).described() == "env 'OPENAI_API_KEY'"

    def test_a_file_reference_names_the_path(self):
        assert "run/secrets" in SecretRef.parse({"file": "/run/secrets/x"}).described()

    def test_a_literal_reveals_nothing(self):
        """Any part of a literal is part of a secret, so none of it appears."""
        described = SecretRef.parse("sk-live-abcdef1234567890").described()
        assert described == "a literal value"
        assert "sk-" not in described

    def test_a_literal_is_written_back_redacted(self):
        """as_dict is what a tool rewriting a config would call, so writing
        the real value would be the exact mistake this prevents."""
        assert SecretRef.parse("sk-live-secret").as_dict() == {"literal": REDACTED}

    def test_a_reference_round_trips(self):
        original = {"env": "OPENAI_API_KEY"}
        assert SecretRef.parse(original).as_dict() == original

    def test_a_default_round_trips(self):
        original = {"env": "AWS_REGION", "default": "us-east-1"}
        assert SecretRef.parse(original).as_dict() == original

    def test_optionality_round_trips(self):
        original = {"env": "OPTIONAL_KEY", "required": False}
        assert SecretRef.parse(original).as_dict() == original
