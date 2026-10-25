"""Printing what the policies permit.

A policy is configured in code, so a shell has no way to see what a running
application allows. This prints the defaults, which is the answer to "what
do I get if I configure nothing".
"""

from __future__ import annotations

from secretref import Severity
from secretref.cli import ExitCode, main


class TestPolicyCommand:
    def test_it_exits_zero(self):
        assert main(["policy"]) == ExitCode.OK

    def test_it_reports_all_three(self, capsys):
        main(["policy"])
        printed = capsys.readouterr().out
        assert "command references" in printed
        assert "file references" in printed
        assert "environment references" in printed

    def test_it_shows_commands_are_off(self, capsys):
        main(["policy"])
        assert "command references: off" in capsys.readouterr().out

    def test_it_shows_the_file_roots(self, capsys):
        main(["policy"])
        assert "/run/secrets" in capsys.readouterr().out

    def test_it_says_these_are_defaults(self, capsys):
        """Otherwise a reader would take it for the running configuration."""
        main(["policy"])
        assert "defaults" in capsys.readouterr().out


class TestSeverityOrdering:
    """`sorted` and `max` have to mean what they look like.

    Needed by the CLI, which prints errors before notes and reports the worst
    severity in its JSON.
    """

    def test_severities_sort_most_severe_first(self):
        assert sorted([Severity.NOTE, Severity.ERROR, Severity.WARNING]) == [
            Severity.ERROR,
            Severity.WARNING,
            Severity.NOTE,
        ]

    def test_worst_picks_the_most_severe(self):
        assert Severity.worst([Severity.NOTE, Severity.WARNING]) is Severity.WARNING

    def test_worst_of_nothing_is_none(self):
        assert Severity.worst([]) is None

    def test_comparing_with_something_else_is_not_implemented(self):
        """Rather than a confusing TypeError from deep inside sorted()."""
        assert Severity.ERROR.__lt__("error") is NotImplemented

    def test_the_values_stay_strings(self):
        """They are the wire format, so making them integers for ordering
        would put the output at the mercy of the comparison."""
        assert Severity.ERROR.value == "error"
