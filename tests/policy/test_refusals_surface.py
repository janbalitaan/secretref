"""A policy refusal has to reach the caller, and reach the audit.

Two ways it could quietly not. `required: false` and `default` describe
whether a secret is *absent*, so neither may turn a refusal into an empty
string. And `is_resolvable` catching too narrow an exception made the audit
crash on exactly the config it existed to report.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from secretref import (
    CommandNotAllowedError,
    CommandPolicy,
    EnvironmentPolicy,
    FileNotAllowedError,
    FilePolicy,
    SecretRef,
    Severity,
    VariableNotAllowedError,
    audit,
    load,
)


@pytest.fixture
def forbidden(tmp_path, monkeypatch):
    """One reference of each form that policy will refuse."""
    monkeypatch.setenv("FORBIDDEN_VAR", "value")
    outside = tmp_path / "forbidden"
    outside.write_text("value")
    secrets = tmp_path / "secrets"
    secrets.mkdir()

    FilePolicy().restrict(secrets)
    EnvironmentPolicy().restrict(prefixes=["ALLOWED_"])
    CommandPolicy().forbid()

    return {
        "env": ({"env": "FORBIDDEN_VAR"}, VariableNotAllowedError),
        "file": ({"file": str(outside)}, FileNotAllowedError),
        "command": ({"command": "echo hi"}, CommandNotAllowedError),
    }


class TestRefusalsReachTheCaller:
    def test_each_form_raises(self, forbidden):
        for mapping, expected in forbidden.values():
            with pytest.raises(expected):
                SecretRef.parse(mapping).resolve()

    def test_required_false_does_not_swallow_a_refusal(self, forbidden):
        """`required: false` means the secret may be absent, not that the
        config may ask for something it is not permitted to."""
        for mapping, expected in forbidden.values():
            with pytest.raises(expected):
                SecretRef.parse({**mapping, "required": False}).resolve()

    def test_a_default_does_not_swallow_a_refusal(self, forbidden):
        for mapping, expected in forbidden.values():
            with pytest.raises(expected):
                SecretRef.parse({**mapping, "default": "fallback"}).resolve()

    def test_every_refusal_is_a_permission_error(self, forbidden):
        """So `except PermissionError` catches all three alongside the
        filesystem refusals a caller already handles."""
        for mapping, _ in forbidden.values():
            with pytest.raises(PermissionError):
                SecretRef.parse(mapping).resolve()


class TestRefusalsReachTheAudit:
    def test_is_resolvable_answers_rather_than_raising(self, forbidden):
        """It caught only ResolutionError, so a refusal propagated — and the
        audit died on the config it was meant to report."""
        for mapping, _ in forbidden.values():
            assert SecretRef.parse(mapping).is_resolvable() is False

    def test_refusal_explains_a_forbidden_reference(self, forbidden):
        mapping, _ = forbidden["env"]
        assert "does not permit" in SecretRef.parse(mapping).refusal()

    def test_refusal_is_empty_for_a_permitted_reference(self):
        """A reference that is allowed but unset is not a refusal: the
        environment is wrong, not the config."""
        EnvironmentPolicy().relax()
        assert SecretRef.parse({"env": "DEFINITELY_NOT_SET"}).refusal() == ""

    def test_refusal_is_empty_for_a_resolvable_reference(self, monkeypatch):
        monkeypatch.setenv("PRESENT", "value")
        assert SecretRef.parse({"env": "PRESENT"}).refusal() == ""

    def test_the_audit_reports_a_refusal_instead_of_crashing(self, tmp_path, forbidden):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"env": "FORBIDDEN_VAR"}}))

        findings = audit(load(path))
        assert len(findings) == 1
        assert findings[0].severity is Severity.ERROR
        assert "refused by policy" in findings[0].message

    def test_a_refusal_is_an_error_outside_a_repository_too(self, tmp_path, forbidden):
        """Unlike a literal secret, this has nothing to do with publishing.
        The application will not start, repository or no repository."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"env": "FORBIDDEN_VAR"}}))
        assert audit(load(path))[0].severity is Severity.ERROR

    def test_the_remedy_points_at_the_policy(self, tmp_path, forbidden):
        """A refusal means the config is wrong, so the fix is the policy or
        the reference — not the deployment."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"env": "FORBIDDEN_VAR"}}))
        assert "policy" in audit(load(path))[0].remedy

    def test_a_refusal_and_an_absence_are_reported_differently(self, tmp_path, forbidden):
        """One means fix the config, the other means fix the deployment."""
        path = tmp_path / "config.json"
        path.write_text(
            json.dumps(
                {
                    "refused": {"env": "FORBIDDEN_VAR"},
                    "absent": {"env": "ALLOWED_BUT_UNSET"},
                }
            )
        )
        findings = {finding.path: finding for finding in audit(load(path))}
        assert findings["refused"].severity is Severity.ERROR
        assert findings["absent"].severity is Severity.NOTE

    def test_a_refusal_never_carries_a_value(self, tmp_path, forbidden):
        """Findings go to logs and CI output."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": {"env": "FORBIDDEN_VAR"}}))
        assert "value" not in str(audit(load(path))[0]).replace("values", "")


class TestPolicyChecksCoverEveryForm:
    """`refusal()` asks the relevant policy and runs nothing.

    Called directly rather than through the audit, which checks `malformed`
    first — so these reach paths the audit short-circuits past.
    """

    def test_a_literal_is_never_refused(self):
        """There is no policy for a literal: the value is already here, and
        `audit` is what objects to it being here."""
        assert SecretRef.parse("sk-live-abcdef1234567890").refusal() == ""

    def test_an_unparseable_command_reads_as_empty_to_the_policy(self):
        """The policy sees no argument list and refuses. `malformed()` is
        what tells a reader it was a syntax error rather than a blank."""
        CommandPolicy().allow("op")
        assert "empty command" in SecretRef.parse({"command": 'op "unclosed'}).refusal()

    def test_a_permitted_command_is_not_refused_and_does_not_run(self, tmp_path):
        """The check validates the parsed arguments; it starts nothing."""
        marker = tmp_path / "ran"
        CommandPolicy().allow("sh")
        reference = SecretRef.parse({"command": f"sh -c 'touch {marker}'"})
        assert reference.refusal() == ""
        assert not marker.exists()

    def test_a_file_outside_the_roots_is_refused_without_being_read(self, tmp_path):
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        outside = tmp_path / "elsewhere"
        outside.write_text("value")
        FilePolicy().restrict(secrets)
        assert (
            "outside the permitted roots" in SecretRef.parse({"file": str(outside)}).refusal()
        )
