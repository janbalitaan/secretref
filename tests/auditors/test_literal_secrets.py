"""Literals the audit should object to, and values it should not."""

from __future__ import annotations

import json
import subprocess

import pytest

from secretref import Severity, audit, load, loads


def write(directory, data) -> object:
    """Put a config in a directory and load it."""
    path = directory / "config.json"
    path.write_text(json.dumps(data))
    return load(path)


@pytest.fixture
def repository(tmp_path):
    """A directory that is a working copy."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


class TestLiteralSecrets:
    def test_a_literal_outside_a_repository_is_a_warning(self, tmp_path):
        config = write(tmp_path, {"api_key": "sk-live-abcdef1234567890"})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.WARNING
        assert not findings[0].blocking

    def test_a_literal_inside_a_repository_is_an_error(self, repository):
        """One commit from a remote, and history keeps it after the fix."""
        config = write(repository, {"api_key": "sk-live-abcdef1234567890"})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.ERROR
        assert findings[0].blocking

    def test_the_error_says_to_rotate(self, repository):
        """Removing the value does not remove it from history."""
        config = write(repository, {"api_key": "sk-live-abcdef1234567890"})
        assert "rotate" in audit(config)[0].remedy

    def test_a_reference_is_not_flagged(self, repository, monkeypatch):
        monkeypatch.setenv("REAL_KEY", "sk-fine")
        config = write(repository, {"api_key": {"env": "REAL_KEY"}})
        assert audit(config) == []

    def test_a_finding_never_carries_the_value(self, repository):
        """Findings go to logs and CI output, so they have to be safe there."""
        secret = "sk-live-abcdef1234567890"
        config = write(repository, {"api_key": secret})
        for finding in audit(config):
            assert secret not in str(finding)

    def test_the_path_locates_the_value(self, repository):
        config = write(repository, {"providers": [{"api_key": "sk-live-abcdef1234"}]})
        assert audit(config)[0].path == "providers.0.api_key"

    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "apiKey",
            "password",
            "secret",
            "token",
            "client_secret",
            "access_key",
            "private_key",
            "credential",
            "dsn",
            "connection_string",
        ],
    )
    def test_keys_that_suggest_a_credential(self, repository, key):
        config = write(repository, {key: "sk-live-abcdef1234567890"})
        assert audit(config), f"{key} was not checked"

    @pytest.mark.parametrize(
        "key", ["name", "region", "model", "timeout", "description", "url", "monkey"]
    )
    def test_keys_that_do_not(self, repository, key):
        """A long string under an innocuous key is not a secret."""
        config = write(repository, {key: "a perfectly ordinary long value"})
        assert audit(config) == [], f"{key} was flagged"

    @pytest.mark.parametrize(
        "value",
        [
            "your-api-key-here",
            "changeme",
            "TODO",
            "<your-key>",
            "{{API_KEY}}",
            "${OPENAI_KEY}",
            "sk-xxxxxxxxxxxx",
            "replace-me",
            "example-secret",
        ],
    )
    def test_placeholders_are_only_notes(self, repository, value):
        """Flagging filler is how an audit trains people to ignore it."""
        config = write(repository, {"api_key": value})
        findings = audit(config)
        assert all(not finding.blocking for finding in findings)

    def test_a_short_value_is_not_treated_as_a_secret(self, repository):
        """More often a flag or a placeholder than a credential."""
        config = write(repository, {"api_key": "abc"})
        assert audit(config) == []

    def test_an_unresolvable_reference_is_a_note(self, repository):
        config = write(repository, {"api_key": {"env": "DEFINITELY_NOT_SET"}})
        findings = audit(config)
        assert len(findings) == 1
        assert findings[0].severity is Severity.NOTE
        assert not findings[0].blocking

    def test_errors_sort_before_warnings_and_notes(self, repository):
        config = write(
            repository,
            {
                "api_key": "sk-live-abcdef1234567890",
                "token": {"env": "DEFINITELY_NOT_SET"},
            },
        )
        severities = [finding.severity for finding in audit(config)]
        assert severities == [Severity.ERROR, Severity.NOTE]

    def test_a_config_loaded_from_a_string_cannot_detect_a_repository(self):
        """No path means no directory to look in, so it degrades to a warning
        rather than guessing."""
        findings = audit(loads(json.dumps({"api_key": "sk-live-abcdef1234567890"})))
        assert findings[0].severity is Severity.WARNING
