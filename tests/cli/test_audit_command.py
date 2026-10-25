"""Auditing from a shell, which is what a pipeline runs.

The exit status is the interface, so most of these assert on that rather
than on what was printed.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from secretref.cli import ExitCode, main


@pytest.fixture
def repository(tmp_path):
    """A working copy, where a literal secret is an error."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def write(directory: Path, data: dict) -> Path:
    path = directory / "config.json"
    path.write_text(json.dumps(data))
    return path


class TestAuditCommand:
    def test_a_clean_config_exits_zero(self, tmp_path):
        write(tmp_path, {"host": "db.internal", "port": 5432})
        assert main(["audit", "--root", str(tmp_path)]) == ExitCode.OK

    def test_a_literal_in_a_repository_exits_one(self, repository):
        write(repository, {"api_key": "sk-live-abcdef1234567890"})
        assert main(["audit", "--root", str(repository)]) == ExitCode.FINDINGS

    def test_a_missing_config_exits_two(self, tmp_path):
        """Separate from a finding, so a pipeline can tell "your config has a
        problem" from "this tool was used wrongly"."""
        assert main(["audit", "--root", str(tmp_path)]) == ExitCode.USAGE

    def test_an_unparseable_config_exits_two(self, tmp_path):
        (tmp_path / "config.json").write_text("{not json")
        assert main(["audit", "--root", str(tmp_path)]) == ExitCode.USAGE

    def test_a_named_path_is_used(self, tmp_path):
        path = tmp_path / "elsewhere.json"
        path.write_text(json.dumps({"host": "x"}))
        assert main(["audit", str(path)]) == ExitCode.OK

    def test_a_warning_alone_does_not_block(self, tmp_path):
        """A literal outside a repository is careless but contained, so it
        should not stop a build by default."""
        write(tmp_path, {"api_key": "sk-live-abcdef1234567890"})
        assert main(["audit", "--root", str(tmp_path)]) == ExitCode.OK

    def test_strict_makes_a_warning_block(self, tmp_path):
        write(tmp_path, {"api_key": "sk-live-abcdef1234567890"})
        assert main(["audit", "--root", str(tmp_path), "--strict"]) == ExitCode.FINDINGS

    def test_strict_does_not_promote_a_note(self, tmp_path):
        """A note is information, not a problem. Promoting those would make
        --strict unusable."""
        write(tmp_path, {"api_key": {"env": "DEFINITELY_NOT_SET"}})
        assert main(["audit", "--root", str(tmp_path), "--strict"]) == ExitCode.OK


class TestOutput:
    def test_it_reports_each_finding(self, repository, capsys):
        write(repository, {"api_key": "sk-live-abcdef1234567890"})
        main(["audit", "--root", str(repository)])
        printed = capsys.readouterr().out
        assert "api_key" in printed
        assert "inside a repository" in printed

    def test_it_never_prints_a_value(self, repository, capsys):
        """The output goes to a build log."""
        secret = "sk-live-abcdef1234567890"
        write(repository, {"api_key": secret})
        main(["audit", "--root", str(repository)])
        assert secret not in capsys.readouterr().out

    def test_errors_are_printed_before_notes(self, repository, capsys):
        write(
            repository,
            {
                "api_key": "sk-live-abcdef1234567890",
                "other": {"env": "DEFINITELY_NOT_SET"},
            },
        )
        main(["audit", "--root", str(repository)])
        printed = capsys.readouterr().out
        assert printed.index("error:") < printed.index("note:")

    def test_a_clean_config_says_so(self, tmp_path, capsys):
        write(tmp_path, {"host": "x"})
        main(["audit", "--root", str(tmp_path)])
        assert "nothing to report" in capsys.readouterr().out

    def test_it_counts_by_severity(self, repository, capsys):
        write(
            repository,
            {
                "api_key": "sk-live-abcdef1234567890",
                "other": {"env": "DEFINITELY_NOT_SET"},
            },
        )
        main(["audit", "--root", str(repository)])
        assert "1 error, 1 note" in capsys.readouterr().out

    def test_a_config_error_goes_to_stderr(self, tmp_path, capsys):
        """So a pipeline capturing stdout for findings is not confused by it."""
        main(["audit", "--root", str(tmp_path)])
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert captured.out == ""


class TestJsonOutput:
    def test_it_is_valid_json(self, repository, capsys):
        write(repository, {"api_key": "sk-live-abcdef1234567890"})
        main(["audit", "--root", str(repository), "--json"])
        json.loads(capsys.readouterr().out)

    def test_it_carries_the_worst_severity(self, repository, capsys):
        write(repository, {"api_key": "sk-live-abcdef1234567890"})
        main(["audit", "--root", str(repository), "--json"])
        assert json.loads(capsys.readouterr().out)["worst"] == "error"

    def test_it_counts_the_blocking_findings(self, repository, capsys):
        write(repository, {"api_key": "sk-live-abcdef1234567890"})
        main(["audit", "--root", str(repository), "--json"])
        assert json.loads(capsys.readouterr().out)["blocking"] == 1

    def test_worst_is_null_when_nothing_was_found(self, tmp_path, capsys):
        write(tmp_path, {"host": "x"})
        main(["audit", "--root", str(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["worst"] is None

    def test_it_says_whether_it_resolved(self, tmp_path, capsys):
        write(tmp_path, {"host": "x"})
        main(["audit", "--root", str(tmp_path), "--json"])
        assert json.loads(capsys.readouterr().out)["resolved"] is False

    def test_it_never_carries_a_value(self, repository, capsys):
        secret = "sk-live-abcdef1234567890"
        write(repository, {"api_key": secret})
        main(["audit", "--root", str(repository), "--json"])
        assert secret not in capsys.readouterr().out
