"""The two ways this is invoked, and the one place it exits.

`main()` returns a status so it can be tested. `run()` exits with it, which
is what a console script has to do — and `python -m secretref` has to work
too, because in a container the console script is often not on PATH.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from secretref.cli import ExitCode, build_parser, run


class TestEntryPoints:
    def test_run_exits_rather_than_returning(self, monkeypatch, tmp_path):
        """A console script's return value is ignored, so it has to exit."""
        monkeypatch.setattr(sys, "argv", ["secretref", "audit", "--root", str(tmp_path)])
        with pytest.raises(SystemExit) as caught:
            run()
        assert caught.value.code == ExitCode.USAGE

    def test_python_dash_m_works(self, tmp_path):
        """Often the only way to reach it inside a container."""
        finished = subprocess.run(
            [sys.executable, "-m", "secretref", "policy"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert finished.returncode == ExitCode.OK
        assert "command references" in finished.stdout

    def test_a_command_is_required(self):
        """Running it bare should say what it can do, not do nothing."""
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_help_lists_every_command(self, capsys):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--help"])
        printed = capsys.readouterr().out
        for command in ("audit", "show", "policy"):
            assert command in printed

    def test_the_epilog_explains_the_exit_status(self, capsys):
        """It is the interface a pipeline uses, so it belongs in --help."""
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--help"])
        assert "exit status" in capsys.readouterr().out
