"""Printing what the policies currently permit."""

from __future__ import annotations

import sys
from typing import TextIO

from secretref.cli.exit_codes import ExitCode
from secretref.policies import CommandPolicy, EnvironmentPolicy, FilePolicy


class PolicyCommand:
    """Reports what each policy permits.

    What this is for: a policy is configured in code, so the only way to see
    what a deployment actually allows is to ask. Printing it at startup, or
    reading it from a shell, beats inferring it from a refusal.

    Shows the defaults when run from a shell, since nothing has configured
    them in that process — which is itself the useful answer to "what do I
    get if I do nothing".
    """

    def __init__(self, out: TextIO | None = None) -> None:
        self._out = out or sys.stdout

    def run(self) -> ExitCode:
        """Print each policy and return the status to exit with."""
        print("These are the defaults. A policy is configured in code, so a", file=self._out)
        print("running application may permit more or less than this.", file=self._out)
        print(file=self._out)
        for policy in (CommandPolicy(), FilePolicy(), EnvironmentPolicy()):
            print(f"  {policy.describe()}", file=self._out)
        return ExitCode.OK
