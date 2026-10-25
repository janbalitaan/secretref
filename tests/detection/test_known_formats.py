"""Credentials whose issuers publish a shape.

The one kind of secret identifiable from the value alone, which is what makes
it the only check that survives a key name an audit cannot predict.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from secretref import audit, load
from secretref.auditors.known_format import KnownFormat

# Built from repeated characters rather than written out as realistic keys.
# A fixture that looks live is flagged by GitHub's push protection and by
# every scanner a contributor runs, and a library about finding secrets should
# not be the repository that trips those. The patterns care about shape, so
# shape is all these need.
RECOGNIZED = [
    ("an AWS access key ID", "AKIAIOSFODNN7EXAMPLE"),
    ("an AWS access key ID", "ASIAY34FZKBOKMUTVV7A"),
    ("a GitHub token", "ghp_" + "a" * 36),
    ("a GitHub token", "gho_" + "b" * 36),
    ("a Stripe secret key", "sk_live_" + "0" * 24),
    ("a Stripe secret key", "rk_test_" + "0" * 24),
    ("a Slack token", "xoxb-123456789012-abcdefghijkl"),
    ("a Google API key", "AIza" + "c" * 35),
    ("an OpenAI project key", "sk-proj-" + "d" * 40),
    ("an OpenAI API key", "sk-" + "d" * 48),
    ("an Anthropic API key", "sk-ant-" + "e" * 32),
    ("a npm access token", "npm_" + "f" * 36),
    ("a HashiCorp Vault token", "hvs." + "g" * 30),
    ("a private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
    ("a JSON Web Token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"),
    (
        "a database connection string with a password",
        "postgresql://app:hunter2@db.internal:5432/billing",
    ),
    (
        "a database connection string with a password",
        "mongodb+srv://user:p4ssw0rd@cluster.mongodb.net/db",
    ),
]

NOT_CREDENTIALS = [
    "db.internal",
    # A loose "sk-" rule claims these, and a wrong name on a finding sends
    # someone to rotate a key at a provider they do not use.
    "sk-live-abcdef1234567890",
    "sk-my-internal-thing-here",
    "resnet50",
    "us-east-1",
    "postgresql://app@db.internal:5432/billing",  # no password in it
    "a reasonable summary of what this service does",
    "/run/secrets/database-password",
    "sk-",
    "AKIA",
]


class TestIdentifyingKnownFormats:
    @pytest.mark.parametrize(("expected", "value"), RECOGNIZED)
    def test_a_published_format_is_named(self, expected, value):
        """Naming it tells a reader what to rotate and where."""
        assert KnownFormat.identify(value) == expected

    @pytest.mark.parametrize("value", NOT_CREDENTIALS)
    def test_ordinary_configuration_is_not_a_credential(self, value):
        assert KnownFormat.identify(value) == ""

    def test_matches_agrees_with_identify(self):
        assert KnownFormat.matches("AKIAIOSFODNN7EXAMPLE")
        assert not KnownFormat.matches("db.internal")

    def test_a_credential_embedded_in_a_longer_string_is_found(self):
        """A connection string or a header often carries one inline."""
        assert KnownFormat.identify("Bearer ghp_" + "a" * 36) == "a GitHub token"


class TestTheAuditUsesTheValue:
    """The key name is what an audit cannot depend on."""

    @pytest.fixture
    def repository(self, tmp_path):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        return tmp_path

    def test_a_credential_under_an_innocuous_key_is_found(self, repository):
        """This is the case key-name matching misses entirely: nothing about
        "tracking.ref" suggests a credential."""
        path = repository / "config.json"
        path.write_text(json.dumps({"tracking": {"ref": "ghp_" + "a" * 36}}))
        findings = audit(load(path))
        assert len(findings) == 1
        assert "a GitHub token" in findings[0].message

    def test_it_says_to_rotate_rather_than_move(self, repository):
        """A value matching a published format is live, so moving it is not
        enough."""
        path = repository / "config.json"
        path.write_text(json.dumps({"x": "AKIAIOSFODNN7EXAMPLE"}))
        assert "rotate" in audit(load(path))[0].remedy

    def test_it_is_an_error_outside_a_repository_too(self, tmp_path):
        """A placeholder is a judgement call; a published format is not."""
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"x": "AKIAIOSFODNN7EXAMPLE"}))
        finding = audit(load(path))[0]
        assert finding.blocking

    def test_it_does_not_double_report(self, repository):
        """A credential under a secret-looking key is one finding, not two."""
        path = repository / "config.json"
        path.write_text(json.dumps({"api_key": "AKIAIOSFODNN7EXAMPLE"}))
        assert len(audit(load(path))) == 1

    def test_an_ordinary_config_is_still_clean(self, repository):
        path = repository / "config.json"
        path.write_text(json.dumps({"host": "db.internal", "port": 5432, "model": "resnet50"}))
        assert audit(load(path)) == []
