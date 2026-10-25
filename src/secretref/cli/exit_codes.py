"""What this program's exit status means.

Named rather than written as literals, because a CI pipeline branches on
them and a number in a shell script is a number nobody can look up.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """The status this program exits with.

    Three values, and the distinction between the last two is what a
    pipeline needs: a config with a problem in it is a different event from
    a command that could not run at all.
    """

    # Nothing blocking was found. Warnings and notes may still have printed.
    OK = 0

    # At least one blocking finding. The build should stop.
    FINDINGS = 1

    # The command itself could not run: no config, bad arguments, a file that
    # will not parse. Distinct from FINDINGS so a pipeline can tell "your
    # config has a problem" from "this tool was used wrongly".
    USAGE = 2
