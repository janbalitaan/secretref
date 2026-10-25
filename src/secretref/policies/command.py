"""What a command reference is permitted to do.

`{"command": "op read op://vault/key"}` is the most useful reference form and
the only dangerous one. The others read a variable or a file; this one starts
a process, so a config file that can be written is a config file that can run
code.

Four things that followed from that, each closing something measured rather
than imagined:

**Off by default.** A config naming a command does nothing until an operator
says otherwise. This is the only one of the four that matters on its own —
the rest reduce the damage, this one removes the capability.

**An allowlist.** `allow("op", "vault")` permits those and refuses everything
else, so a config that gains a `{"command": "curl ..."}` is refused rather
than run.

**A minimal environment.** A subprocess inheriting the parent's environment
can read every other secret the process holds, which defeats the point of
resolving them one at a time. Only PATH, HOME, LANG and TMPDIR are passed
unless the caller names more.

**An output cap.** A secret is short. A command producing more than the cap
is either the wrong command or an attempt to exhaust memory.

What was already true and still is: the command is split with `shlex` and run
without a shell, so a locator cannot chain commands or open a pipe.

None of this makes a writable config safe. An attacker who can edit your
config and who is allowed to run `op` can read everything `op` can read. The
policy narrows what a mistake costs; it does not make the config trusted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import shutil
from threading import Lock
from typing import ClassVar

from secretref.constants import (
    MINIMAL_ENVIRONMENT,
)
from secretref.exceptions import CommandNotAllowedError
from secretref.policies.settings.command import CommandSettings


class CommandPolicy:
    """Process-wide rules for running a command reference.

    A singleton, for the same reason `ResolutionCache` is one: this is a
    decision made once at startup that every resolution has to see. A
    per-reference policy would let one reference in a config opt itself into
    privileges the operator never granted, which is precisely backwards.
    """

    _instance: ClassVar[CommandPolicy | None] = None
    _singleton_lock: ClassVar[Lock] = Lock()

    def __new__(cls) -> CommandPolicy:
        """Return the one instance, creating it on first use."""
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialize()
                    cls._instance = instance
        return cls._instance

    def _initialize(self) -> None:
        """Start from the safe position: nothing may run."""
        self._settings = CommandSettings()

    # -- configuration -----------------------------------------------------

    def allow(
        self,
        *executables: str,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        pass_environment: Sequence[str] | None = None,
        working_directory: Path | str | None = None,
        require_absolute: bool = False,
    ) -> None:
        """Permit the named executables, and nothing else.

        Naming none permits any executable, which is the pre-policy
        behavior and has to be asked for explicitly:

            CommandPolicy().allow("op", "vault")   # these two only
            CommandPolicy().allow()                # anything — say why

        `pass_environment` adds to the minimal set rather than replacing it,
        because a CLI that cannot see PATH cannot start.
        """
        current = self._settings
        changes: dict[str, object] = {
            "enabled": True,
            "allowed": frozenset(executables),
            # Resolved now rather than at use. `allow("op")` would otherwise
            # permit whatever `op` meant on PATH at resolution time, and an
            # attacker who can set PATH can make that their own script.
            # Resolving here pins it while PATH is still the one the operator
            # started the process with.
            "resolved": self._resolve_executables(executables),
            "require_absolute": require_absolute,
        }
        if timeout_seconds is not None:
            changes["timeout"] = timeout_seconds
        if max_output_bytes is not None:
            changes["max_output"] = max_output_bytes
        if pass_environment is not None:
            changes["passthrough"] = MINIMAL_ENVIRONMENT + tuple(pass_environment)
        if working_directory is not None:
            changes["working_directory"] = Path(working_directory)
        # One assignment, so a reader sees the old snapshot or the new one
        # and never a mixture of the two.
        self._settings = current.with_changes(**changes)

    @staticmethod
    def _resolve_executables(names: tuple[str, ...]) -> frozenset[str]:
        """Find each named executable on PATH, as it is right now.

        A name that is not found is simply absent from the result, which
        leaves the name-based check to handle it. That matters because a
        policy is often configured before the tool is installed — in a
        container built in stages, say — and failing at configuration time
        would be worse than checking by name later.
        """
        found = set()
        for name in names:
            if Path(name).is_absolute():
                found.add(str(Path(name).resolve()))
                continue
            located = shutil.which(name)
            if located:
                found.add(str(Path(located).resolve()))
        return frozenset(found)

    def forbid(self) -> None:
        """Refuse every command reference. The starting position."""
        self._initialize()

    # -- what resolution asks ----------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether any command reference may run."""
        return self._settings.enabled

    @property
    def timeout(self) -> float:
        """Seconds a command may take."""
        return self._settings.timeout

    @property
    def max_output(self) -> int:
        """Bytes of output to accept."""
        return self._settings.max_output

    @property
    def working_directory(self) -> Path | None:
        """Where to run, or None to inherit."""
        return self._settings.working_directory

    def check(self, parts: Sequence[str], described: str) -> None:
        """Refuse a command the policy does not permit.

        Four questions, in order of how cheaply they can be answered and how
        bluntly they refuse: are commands on at all, is there a command, does
        it satisfy the shape this policy demands, and is it one of the
        executables that were allowed.

        `described` is the reference's safe description, so a message names
        which reference was refused without ever quoting its arguments.
        """
        settings = self._settings
        self._check_enabled(settings, described)
        self._check_not_empty(parts, described)

        executable = parts[0]
        self._check_shape(settings, executable, described)
        if settings.allowed:
            self._check_allowed(settings, executable, described)

    @staticmethod
    def _check_enabled(settings: CommandSettings, described: str) -> None:
        """Refuse everything when command references are off."""
        if not settings.enabled:
            raise CommandNotAllowedError(
                f"{described} was refused: command references are off by default. "
                "Enable them deliberately with "
                'CommandPolicy().allow("your-tool"), naming the executables '
                "a config is permitted to run."
            )

    @staticmethod
    def _check_not_empty(parts: Sequence[str], described: str) -> None:
        """Refuse a command with no executable in it."""
        if not parts:
            raise CommandNotAllowedError(f"{described} is an empty command")

    @staticmethod
    def _check_shape(settings: CommandSettings, executable: str, described: str) -> None:
        """Refuse a bare name when this policy demands an absolute path."""
        if settings.require_absolute and not Path(executable).is_absolute():
            raise CommandNotAllowedError(
                f"{described} must name an absolute path under this policy; "
                "a bare name is resolved through PATH, which a caller may control"
            )

    @classmethod
    def _check_allowed(cls, settings: CommandSettings, executable: str, described: str) -> None:
        """Refuse an executable this policy was not configured to permit.

        A pinned absolute path is checked first. If `allow()` found the
        executable, only that exact file satisfies the policy, so a PATH
        change between configuration and use cannot substitute another.
        """
        if cls._matches_pinned_file(settings, executable):
            return
        if Path(executable).name in settings.allowed or executable in settings.allowed:
            cls._check_not_substituted(settings, executable, described)
            return

        permitted = ", ".join(sorted(settings.allowed))
        raise CommandNotAllowedError(
            f"{described} is not permitted. This policy allows: {permitted}"
        )

    @staticmethod
    def _matches_pinned_file(settings: CommandSettings, executable: str) -> bool:
        """Whether this resolves to a file `allow()` pinned."""
        if not settings.resolved:
            return False
        located = shutil.which(executable)
        return bool(located) and str(Path(located).resolve()) in settings.resolved

    @staticmethod
    def _check_not_substituted(
        settings: CommandSettings, executable: str, described: str
    ) -> None:
        """Refuse a name that now resolves somewhere else than when allowed.

        Reached when the name is permitted but did not match a pinned file.
        If the policy pinned anything and this name resolves at all, PATH has
        changed since the policy was configured — which is the substitution
        the pinning exists to catch.
        """
        if settings.resolved and (located := shutil.which(executable)):
            raise CommandNotAllowedError(
                f"{described} resolves to {located}, which is not the file this "
                "policy pinned when it was configured. PATH has changed since then."
            )

    def environment(self) -> Mapping[str, str]:
        """Build the environment a command reference runs with.

        Built by name from the parent's, so a variable the policy does not
        list is invisible to the subprocess — including every other secret
        this process has already resolved.
        """
        return {
            name: os.environ[name] for name in self._settings.passthrough if name in os.environ
        }

    def describe(self) -> str:
        """Summarize what this policy permits, in one line. Safe to log."""
        settings = self._settings
        if not settings.enabled:
            return "command references: off"
        allowed = ", ".join(sorted(settings.allowed)) if settings.allowed else "any executable"
        return (
            f"command references: on ({allowed}), "
            f"timeout {settings.timeout}s, "
            f"output capped at {settings.max_output} bytes, "
            f"{len(settings.passthrough)} environment variables passed"
        )
