"""The CLI must not run a config's commands, and must not lie about them.

Auditing a config from a pull request is the main use, so the tool resolving
a command reference would be remote code execution. But reporting one as
*refused* would be a false error — this tool's policy is not the
application's policy, and it has no way to learn what the application
permits.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from secretref.cli import ExitCode, main


@pytest.fixture
def marker(tmp_path):
    return tmp_path / "the-command-ran"


@pytest.fixture
def config_with_a_command(tmp_path, marker):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_key": {"command": f"sh -c 'touch {marker}'"}}))
    return tmp_path


class TestCommandSafety:
    def test_auditing_does_not_run_it(self, config_with_a_command, marker):
        main(["audit", "--root", str(config_with_a_command)])
        assert not marker.exists()

    def test_it_is_reported_as_unverified_not_refused(self, config_with_a_command, capsys):
        """A false error on a config that works perfectly in the program
        that owns it would train people to ignore the tool."""
        main(["audit", "--root", str(config_with_a_command)])
        printed = capsys.readouterr().out
        assert "not verified" in printed
        assert "refused by policy" not in printed

    def test_unverified_does_not_block(self, config_with_a_command):
        """Not knowing is not the same as knowing something is wrong."""
        assert main(["audit", "--root", str(config_with_a_command)]) == ExitCode.OK

    def test_it_says_commands_were_withheld(self, config_with_a_command, capsys):
        """Silence would let a reader think the config had been checked."""
        main(["audit", "--root", str(config_with_a_command)])
        assert "were not run" in capsys.readouterr().out

    def test_resolve_without_an_allowlist_still_runs_nothing(
        self, config_with_a_command, marker
    ):
        """--resolve is about this config being yours, not about permitting
        anything at all. Without a named executable, nothing runs."""
        main(["audit", "--root", str(config_with_a_command), "--resolve"])
        assert not marker.exists()

    def test_resolve_with_an_allowlist_runs_it(self, config_with_a_command, marker):
        main(
            [
                "audit",
                "--root",
                str(config_with_a_command),
                "--resolve",
                "--allow-command",
                "sh",
            ]
        )
        assert marker.exists()

    def test_the_allowlist_only_permits_what_it_names(
        self, config_with_a_command, marker, capsys
    ):
        main(
            [
                "audit",
                "--root",
                str(config_with_a_command),
                "--resolve",
                "--allow-command",
                "op",
            ]
        )
        assert not marker.exists()
        assert "refused by policy" in capsys.readouterr().out

    def test_a_malformed_command_is_still_reported(self, tmp_path, capsys):
        """Parsing a string runs nothing, so a syntax error is caught
        whether or not commands are verified."""
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        (tmp_path / "config.json").write_text(
            json.dumps({"api_key": {"command": 'op "unclosed'}})
        )
        assert main(["audit", "--root", str(tmp_path)]) == ExitCode.FINDINGS
        assert "not a parseable command" in capsys.readouterr().out


class TestShowReadsNothing:
    def test_showing_does_not_run_a_command(self, config_with_a_command, marker):
        """`show` lists what a config references. It resolves nothing, so it
        is safe against a config from anywhere."""
        main(["show", "--root", str(config_with_a_command)])
        assert not marker.exists()

    def test_it_lists_the_reference(self, config_with_a_command, capsys):
        main(["show", "--root", str(config_with_a_command)])
        printed = capsys.readouterr().out
        assert "api_key" in printed
        assert "command 'sh'" in printed

    def test_it_does_not_print_the_arguments(self, config_with_a_command, capsys):
        """A command's arguments can hold a secret, so only the executable
        is named."""
        main(["show", "--root", str(config_with_a_command)])
        assert "touch" not in capsys.readouterr().out
