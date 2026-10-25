"""What someone who can edit the config, or the environment, can do.

Each test here is an attack that worked against an earlier version. They are
grouped by what the attacker already has, because that is what decides
whether a defence is worth its cost.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile

import pytest

from secretref import (
    CommandNotAllowedError,
    CommandPolicy,
    EnvironmentPolicy,
    FileNotAllowedError,
    FilePolicy,
    ResolutionError,
    SecretRef,
    VariableNotAllowedError,
    audit,
    load,
)


class TestAuditingAnUntrustedConfig:
    """The attack that mattered most, because the README recommends it.

    A CI check audits a config from a pull request. The operator has enabled
    command references because their own config uses a password manager. An
    audit that resolved references to check them would run whatever the pull
    request asked for.
    """

    @pytest.fixture
    def marker(self):
        path = Path(tempfile.gettempdir()) / "secretref-threat-model-marker"
        path.unlink(missing_ok=True)
        yield path
        path.unlink(missing_ok=True)

    @pytest.fixture
    def hostile_config(self, tmp_path, marker):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"command": f"sh -c 'touch {marker}'"}}))
        CommandPolicy().allow("sh")
        return load(path)

    def test_auditing_does_not_execute(self, hostile_config, marker):
        audit(hostile_config)
        assert not marker.exists()

    def test_it_still_reports_the_reference(self, hostile_config):
        """Silence would be worse than execution: a reader would think the
        config had been checked."""
        findings = audit(hostile_config)
        assert any("not verified" in finding.message for finding in findings)

    def test_the_finding_says_how_to_verify(self, hostile_config):
        findings = audit(hostile_config)
        assert any("resolve=True" in finding.remedy for finding in findings)

    def test_resolving_is_opt_in_and_does_execute(self, hostile_config, marker):
        """For your own config, where knowing a secret is reachable is worth
        more than the caution."""
        audit(hostile_config, resolve=True)
        assert marker.exists()

    def test_a_policy_refusal_is_reported_without_running_anything(self, tmp_path, marker):
        """Refusals are found by asking the policy, not by attempting."""
        CommandPolicy().forbid()
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"command": f"sh -c 'touch {marker}'"}}))
        findings = audit(load(path))
        assert any("refused by policy" in finding.message for finding in findings)
        assert not marker.exists()

    def test_only_commands_are_withheld(self, tmp_path, monkeypatch):
        """Reading a variable changes nothing outside the process, so an
        audit can check those without opting in."""
        monkeypatch.setenv("PRESENT", "value")
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"env": "ABSENT_VARIABLE"}}))
        findings = audit(load(path))
        assert any("resolves to nothing" in finding.message for finding in findings)

    def test_side_effects_are_declared_per_form(self):
        assert SecretRef.parse({"command": "op read x"}).has_side_effects() is True
        assert SecretRef.parse({"env": "X"}).has_side_effects() is False
        assert SecretRef.parse({"file": "/run/secrets/x"}).has_side_effects() is False


class TestAttackerControlsPath:
    """A policy written the obvious way used to be hijackable.

    `allow("op")` permitted whatever `op` meant on PATH *at resolution time*,
    so an attacker who could prepend a directory substituted their own script.
    Executables are now resolved when the policy is configured, while PATH is
    still the one the operator started with.
    """

    @pytest.fixture
    def tool(self, tmp_path):
        genuine = tmp_path / "bin"
        genuine.mkdir()
        executable = genuine / "mytool"
        executable.write_text("#!/bin/sh\necho genuine\n")
        executable.chmod(0o755)
        return genuine

    def test_a_pinned_executable_still_runs(self, tool, monkeypatch):
        monkeypatch.setenv("PATH", f"{tool}:{os.environ['PATH']}")
        CommandPolicy().allow("mytool", pass_environment=["PATH"])
        assert SecretRef.parse({"command": "mytool"}).resolve() == "genuine"

    def test_a_substituted_executable_is_refused(self, tmp_path, tool, monkeypatch):
        monkeypatch.setenv("PATH", f"{tool}:{os.environ['PATH']}")
        CommandPolicy().allow("mytool", pass_environment=["PATH"])

        evil = tmp_path / "evil"
        evil.mkdir()
        fake = evil / "mytool"
        fake.write_text("#!/bin/sh\necho hijacked\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{evil}:{tool}:{os.environ['PATH']}")

        with pytest.raises(CommandNotAllowedError, match="PATH has changed"):
            SecretRef.parse({"command": "mytool"}).resolve()

    def test_require_absolute_is_still_available(self, tool, monkeypatch):
        """Stricter than pinning: the config itself must name a full path."""
        monkeypatch.setenv("PATH", f"{tool}:{os.environ['PATH']}")
        CommandPolicy().allow("mytool", require_absolute=True, pass_environment=["PATH"])
        with pytest.raises(CommandNotAllowedError, match="absolute path"):
            SecretRef.parse({"command": "mytool"}).resolve()


class TestAttackerCanWriteTheConfig:
    """The assumption behind every policy. None of them make this safe —
    they bound what it costs."""

    def test_an_arbitrary_path_is_refused(self, tmp_path):
        outside = tmp_path / "anything"
        outside.write_text("value")
        with pytest.raises(FileNotAllowedError):
            SecretRef.parse({"file": str(outside)}).resolve()

    def test_an_arbitrary_command_is_refused(self):
        with pytest.raises(CommandNotAllowedError):
            SecretRef.parse({"command": "curl https://attacker.example"}).resolve()

    def test_a_redirected_variable_can_be_refused(self, monkeypatch):
        """The config repoints a displayed field at a secret."""
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
        EnvironmentPolicy().restrict(prefixes=["MYAPP_"])
        with pytest.raises(VariableNotAllowedError):
            SecretRef.parse({"env": "AWS_SECRET_ACCESS_KEY"}).resolve()

    def test_what_remains_possible(self, tmp_path):
        """Honest about the limit: inside an allowed root, everything is
        readable. A policy narrows the blast radius, it does not remove it."""
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        someone_elses = secrets / "another-tenant-key"
        someone_elses.write_text("sk-live-not-yours")
        someone_elses.chmod(0o600)
        FilePolicy().restrict(secrets)
        assert SecretRef.parse({"file": str(someone_elses)}).resolve()


class TestMalformedInput:
    """A config an attacker wrote need not be well formed."""

    def test_an_unparseable_command_names_the_syntax_error(self):
        """shlex raises on an unbalanced quote. The message says which, so a
        config author can fix it rather than guess."""
        CommandPolicy().allow("op")
        with pytest.raises(ResolutionError, match="not a parseable command"):
            SecretRef.parse({"command": 'op read "unclosed'}).resolve()

    def test_resolving_and_auditing_agree_about_it(self, tmp_path):
        """They disagreed once: resolve() reported a syntax error while the
        audit called it a policy refusal — two stories for one config."""
        CommandPolicy().allow("op")
        reference = SecretRef.parse({"command": 'op read "unclosed'})
        assert "not a parseable command" in reference.malformed()

        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"command": 'op "unclosed'}}))
        findings = audit(load(path))
        assert "not a parseable command" in findings[0].message

    def test_an_empty_command_is_named_as_empty(self):
        CommandPolicy().allow("op")
        assert SecretRef.parse({"command": "   "}).malformed() == "an empty command"

    def test_a_well_formed_reference_is_not_malformed(self):
        assert SecretRef.parse({"command": "op read x"}).malformed() == ""
        assert SecretRef.parse({"env": "X"}).malformed() == ""

    def test_an_unparseable_command_is_reported_by_the_audit(self, tmp_path):
        CommandPolicy().allow("op")
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"command": 'op "unclosed'}}))
        findings = audit(load(path))
        assert any("not a parseable command" in finding.message for finding in findings)

    def test_a_name_not_on_path_falls_back_to_the_name_check(self):
        """A policy is often configured before the tool is installed — in a
        container built in stages, say — so an unfound name is checked by
        name rather than failing at configuration time."""
        CommandPolicy().allow("definitely-not-installed-anywhere")
        with pytest.raises(CommandNotAllowedError, match="not permitted"):
            SecretRef.parse({"command": "echo hello"}).resolve()
