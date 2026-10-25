"""Reading a secret that is encrypted at rest.

The docs claim this works through a `command` reference with no new code, so
it is worth a test with real cryptography rather than a stand-in. gpg is used
because it is present nearly everywhere; sops and age behave the same way
from this library's point of view, since all it does is run a program and
take its output.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from secretref import CommandPolicy, audit, load

PASSPHRASE = "unlock-me"
SECRET = "the-actual-database-password"

needs_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")


@pytest.fixture
def encrypted(tmp_path) -> Path:
    """A real encrypted secret, with its passphrase in a secret file."""
    plain = tmp_path / "plain.txt"
    plain.write_text(SECRET)
    blob = tmp_path / "secret.gpg"
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--passphrase",
            PASSPHRASE,
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "--output",
            str(blob),
            str(plain),
        ],
        check=True,
        capture_output=True,
    )
    plain.unlink()

    # Encryption moves the problem to one key, and the key is still a secret
    # delivered the ordinary way.
    passphrase_file = tmp_path / "gpg-passphrase"
    passphrase_file.write_text(PASSPHRASE)
    passphrase_file.chmod(0o600)
    return tmp_path


@pytest.fixture
def config_path(encrypted) -> Path:
    path = encrypted / "config.json"
    path.write_text(
        json.dumps(
            {
                "database": {
                    "host": "db.internal",
                    "password": {
                        "command": (
                            "gpg --batch --quiet --decrypt --passphrase-file "
                            f"{encrypted / 'gpg-passphrase'} "
                            f"{encrypted / 'secret.gpg'}"
                        )
                    },
                }
            }
        )
    )
    return path


@needs_gpg
class TestEncryptedAtRest:
    def test_the_blob_on_disk_does_not_contain_the_secret(self, encrypted):
        """Otherwise the rest of this proves nothing."""
        blob = (encrypted / "secret.gpg").read_bytes()
        assert SECRET.encode() not in blob

    def test_a_command_reference_decrypts_it(self, config_path):
        """The docs claim this needs no new code."""
        CommandPolicy().allow("gpg", pass_environment=["HOME", "PATH"])
        config = load(config_path)
        assert config.secret("database.password").resolve() == SECRET

    def test_auditing_it_decrypts_nothing(self, config_path):
        """The property that has to survive: auditing a config from a pull
        request runs none of its commands, encrypted or not."""
        CommandPolicy().allow("gpg", pass_environment=["HOME", "PATH"])
        findings = audit(load(config_path))
        assert len(findings) == 1
        assert "was not verified" in findings[0].message
        assert not findings[0].blocking

    def test_the_policy_still_applies(self, config_path):
        """Encryption does not exempt a command from the policy."""
        CommandPolicy().forbid()
        findings = audit(load(config_path))
        assert "refused by policy" in findings[0].message

    def test_the_audit_never_prints_the_secret(self, config_path):
        CommandPolicy().allow("gpg", pass_environment=["HOME", "PATH"])
        for finding in audit(load(config_path)):
            assert SECRET not in str(finding)
