"""Running a command and taking its output as the secret.

For a password manager or a cloud secret store, which usually offer a CLI
before they offer a Python client. This is also the only source with side
effects, which is why it is off by default and why an audit never reaches it.
"""

from __future__ import annotations

import shlex
import subprocess

from secretref.exceptions.resolution import ResolutionError
from secretref.policies.command import CommandPolicy


class CommandResolver:
    """Runs a permitted command and takes its output.

    The command is split with shlex and run without a shell, so a locator
    cannot smuggle in a pipeline or a second command. Everything the policy
    bounds — which executables, how long, how much output, which environment
    — is read from it here rather than decided in this class.
    """

    def read(self, locator: str, described: str) -> str:
        """Run the command and return its output, stripped."""
        parts = self._split(locator, described)

        # The policy decides whether this may run at all, emptiness included.
        # Checking emptiness here as well left its check unreachable.
        policy = CommandPolicy()
        policy.check(parts, described)

        finished = self._run(parts, policy, described)
        self._check_status(finished, described)
        return self._checked_output(finished.stdout, policy, described)

    @staticmethod
    def _split(locator: str, described: str) -> list[str]:
        """Split the command into arguments, or raise naming the syntax error."""
        try:
            return shlex.split(locator)
        except ValueError as error:
            raise ResolutionError(f"{described} is not a parseable command: {error}") from error

    @staticmethod
    def _run(
        parts: list[str], policy: CommandPolicy, described: str
    ) -> subprocess.CompletedProcess[str]:
        """Start the command under the policy's limits."""
        try:
            return subprocess.run(  # noqa: S603 - no shell, arguments are split
                parts,
                capture_output=True,
                text=True,
                timeout=policy.timeout,
                check=False,
                # Only the variables the policy names. A subprocess given the
                # parent's whole environment can read every other secret this
                # process holds.
                env=dict(policy.environment()),
                cwd=policy.working_directory,
            )
        except subprocess.TimeoutExpired as error:
            raise ResolutionError(
                f"{described} did not finish within {policy.timeout}s"
            ) from error
        except (OSError, subprocess.SubprocessError) as error:
            raise ResolutionError(f"{described} could not be run: {error}") from error

    @staticmethod
    def _check_status(finished: subprocess.CompletedProcess[str], described: str) -> None:
        """Raise when the command failed, without quoting its stderr.

        A failing secrets CLI often prints the value it was reading, or the
        token it was using, so its output does not go into the message.
        """
        if finished.returncode != 0:
            raise ResolutionError(f"{described} exited with status {finished.returncode}")

    @staticmethod
    def _checked_output(output: str, policy: CommandPolicy, described: str) -> str:
        """Return the output, or raise when there is too much of it."""
        if len(output.encode("utf-8", "ignore")) > policy.max_output:
            raise ResolutionError(
                f"{described} produced more than {policy.max_output} bytes. "
                "A secret is short; this is either the wrong command or an "
                "attempt to exhaust memory."
            )
        return output.strip()
