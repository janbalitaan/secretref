"""Every example and claim in README.md, asserted so the docs cannot drift."""

from __future__ import annotations

from importlib.metadata import requires
import json
import subprocess

import pytest

from secretref import REDACTED, SecretRef, Severity, audit, load

README_CONFIG = {
    "providers": [
        {"name": "openai", "api_key": {"env": "OPENAI_API_KEY"}},
        {"name": "anthropic", "api_key": {"file": "/run/secrets/anthropic"}},
        {"name": "internal", "api_key": {"command": "op read op://vault/key"}},
    ],
    "timeout_seconds": 30,
    "languages": ["en", "fil"],
}


@pytest.fixture
def repository(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(README_CONFIG))
    return path


class TestReadmeClaims:
    def test_the_opening_example(self, repository, monkeypatch):
        """README: get() returns 30 and the list, secret() resolves."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-resolved")
        config = load(repository)
        assert config.get("timeout_seconds") == 30
        assert config.get("languages") == ["en", "fil"]
        assert config.secret("providers.0.api_key").resolve() == "sk-resolved"

    def test_all_three_reference_forms_parse(self, repository):
        """README's table lists env, file and command."""
        config = load(repository)
        assert config.secret("providers.0.api_key").described() == "env 'OPENAI_API_KEY'"
        assert "anthropic" in config.secret("providers.1.api_key").described()
        assert config.secret("providers.2.api_key").described() == "command 'op'"

    def test_a_literal_in_a_repository_is_an_error(self, tmp_path):
        """README: 'a literal secret is an error when there is a repository
        above the file'."""
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": "sk-live-abcdef1234567890"}))
        findings = audit(load(path))
        assert findings[0].severity is Severity.ERROR
        assert findings[0].blocking

    def test_a_literal_outside_one_is_a_warning(self, tmp_path):
        """README: 'outside a repository the same value is a warning'."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": "sk-live-abcdef1234567890"}))
        assert audit(load(path))[0].severity is Severity.WARNING

    def test_the_ci_snippet_works(self, repository, commands_allowed):
        """README's CI example exits non-zero only on a blocking finding."""
        findings = audit(load(repository))
        exit_code = 1 if any(finding.blocking for finding in findings) else 0
        assert exit_code == 0

    def test_described_is_safe_for_logs(self):
        """README: 'safe for logs, error messages and anything a user sees'."""
        secret = "sk-live-abcdef1234567890"
        described = SecretRef.parse(secret).described()
        assert described == "a literal value"
        assert secret not in described

    def test_as_dict_redacts_a_literal(self):
        """README: 'as_dict() writes a literal back as [redacted]'."""
        assert SecretRef.parse("sk-live-secret").as_dict() == {"literal": REDACTED}

    def test_default_and_required_work_as_documented(self):
        """README shows both options in its table."""
        assert SecretRef.parse({"env": "NOT_SET", "required": False}).resolve() == ""
        assert (
            SecretRef.parse({"env": "NOT_SET", "default": "us-east-1"}).resolve() == "us-east-1"
        )

    def test_loading_reads_no_secrets(self, repository):
        """README: 'Loading a config reads no secrets'.

        None of this config's three variables are set, so a load that
        resolved anything would raise.
        """
        config = load(repository)
        assert config.data["providers"][0]["api_key"] == {"env": "OPENAI_API_KEY"}

    def test_the_startup_check_snippet(self, repository, commands_allowed):
        """README: list every missing secret rather than failing on the first."""
        config = load(repository)
        missing = [path for path, ref in config.secrets().items() if not ref.is_resolvable()]
        assert len(missing) == 3

    def test_a_command_cannot_chain(self, commands_allowed):
        """README: 'split with shlex and run without a shell, so a locator
        cannot smuggle in a pipeline or a second command'."""
        assert SecretRef.parse({"command": "echo one; echo two"}).resolve() == "one; echo two"

    def test_it_has_no_dependencies(self):
        """README: 'No dependencies'.

        Read from the installed distribution rather than pyproject.toml,
        because what a user gets is the metadata — and because tomllib is
        only in the standard library from 3.11 while this supports 3.10.
        """
        declared = requires("secretref") or []
        # Optional extras appear with an environment marker; the base install
        # must have none without one.
        required = [item for item in declared if "extra ==" not in item]
        assert required == []

    def test_an_unlisted_secret_is_not_found(self, tmp_path):
        """README limitation: a secret with no recognizable shape under a key
        with no recognizable name is not found."""
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"greeting": "hunter2-not-a-known-shape"}))
        assert audit(load(path)) == []

    def test_repository_detection_is_a_heuristic(self, tmp_path):
        """README limitation: 'a config outside the working copy will be
        judged wrong — in the safe direction, as a warning'."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": "sk-live-abcdef1234567890"}))
        assert audit(load(path))[0].severity is Severity.WARNING
