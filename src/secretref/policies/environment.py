"""Which environment variables a config may reference.

The obvious objection first: the process already holds every variable, so
reading one through a reference grants nothing new. That is true, and it is
beside the point.

The threat is not gaining access to the environment. It is redirecting an
existing data flow to carry something out of it:

    {"support_email": {"env": "SUPPORT_EMAIL"}}           rendered on a page
    {"support_email": {"env": "AWS_SECRET_ACCESS_KEY"}}   also rendered

Same process, same variables, no new access — and now a key is on a public
page. Every field a config exposes is a potential channel: a log line, an
error message, an HTTP response, a metrics label. An allowlist means a field
cannot be repointed at something that was never meant to leave.

Open by default, like `FilePolicy` and unlike `CommandPolicy`. Restricting by
default would reject every config written before the policy existed, for a
threat that requires a writable config — and a library that rejects working
configs on upgrade gets pinned to the old version.
"""

from __future__ import annotations

from collections.abc import Sequence
import os
import re
from threading import Lock
from typing import ClassVar

from secretref.exceptions import VariableNotAllowedError
from secretref.policies.settings import EnvironmentSettings


class EnvironmentPolicy:
    """Process-wide rules for which variables a reference may name.

    A singleton, like the other two: a decision an operator makes once that
    every resolution has to see.
    """

    _instance: ClassVar[EnvironmentPolicy | None] = None
    _singleton_lock: ClassVar[Lock] = Lock()

    def __new__(cls) -> EnvironmentPolicy:
        """Return the one instance, creating it on first use."""
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialize()
                    cls._instance = instance
        return cls._instance

    def _initialize(self) -> None:
        """Start permissive: any variable may be referenced."""
        # Tracked separately from whether there are any rules, because
        # "restricted to nothing" and "not restricted" are different states
        # that would otherwise be indistinguishable — and the first is a
        # useful way to switch environment references off entirely.
        self._settings = EnvironmentSettings()

    # -- configuration -----------------------------------------------------

    def restrict(
        self,
        *names: str,
        prefixes: Sequence[str] = (),
        patterns: Sequence[str] = (),
    ) -> None:
        """Permit only the variables named, prefixed or matched.

        Three mechanisms because projects name variables three ways:

            restrict("DATABASE_PASSWORD", "STRIPE_KEY")   exactly these
            restrict(prefixes=["MYAPP_"])                 a namespace
            restrict(patterns=[r"_PASSWORD$"])            a convention

        Restricting with nothing at all permits nothing, which is a useful
        way to switch environment references off entirely.
        """
        # One assignment, so a reader never sees a half-applied policy.
        self._settings = EnvironmentSettings(
            active=True,
            names=frozenset(names),
            prefixes=tuple(prefixes),
            patterns=tuple(re.compile(pattern) for pattern in patterns),
        )

    def relax(self) -> None:
        """Permit any variable again. The starting position."""
        self._initialize()

    # -- what resolution asks ----------------------------------------------

    @property
    def restricted(self) -> bool:
        """Whether a restriction is in force.

        True after any `restrict()` call, including one naming nothing —
        that case permits no variable at all, which is how environment
        references are switched off.
        """
        return self._settings.active

    def check(self, name: str, described: str) -> None:
        """Refuse a variable the policy does not permit.

        `described` is the reference's safe description, so the message says
        which reference was refused.
        """
        if not self.restricted or self.permits(name):
            return
        raise VariableNotAllowedError(
            f"{described} names a variable this policy does not permit. {self.describe()}"
        )

    def permits(self, name: str) -> bool:
        """Whether a variable may be referenced."""
        settings = self._settings
        if not settings.active:
            return True
        return (
            name in settings.names
            or name.startswith(settings.prefixes)
            or any(pattern.search(name) for pattern in settings.patterns)
        )

    def visible(self) -> dict[str, str]:
        """List the variables a reference could currently read.

        For a startup check or a log line: knowing what a config *may* reach
        is more useful than discovering it from a refusal. Names only — the
        values are what the policy exists to protect.
        """
        return {name: "<set>" for name in sorted(os.environ) if self.permits(name)}

    def describe(self) -> str:
        """Summarize what this policy permits, in one line. Safe to log."""
        settings = self._settings
        if not settings.active:
            return "environment references: any variable"
        parts = []
        if settings.names:
            parts.append(f"names {', '.join(sorted(settings.names))}")
        if settings.prefixes:
            parts.append(f"prefixes {', '.join(settings.prefixes)}")
        if settings.patterns:
            joined = ", ".join(p.pattern for p in settings.patterns)
            parts.append(f"patterns {joined}")
        allowed = "; ".join(parts) if parts else "nothing"
        return f"environment references: {allowed}"
