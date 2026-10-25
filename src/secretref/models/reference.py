"""A named secret, not the secret itself."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import shlex
from types import MappingProxyType

from secretref.cache import ResolutionCache
from secretref.constants import (
    COMMAND_KEY,
    DEFAULT_KEY,
    ENV_KEY,
    FILE_KEY,
    LITERAL_KEY,
    REDACTED,
    REQUIRED_KEY,
    SECRET_KEYS,
)
from secretref.exceptions import (
    CommandNotAllowedError,
    FileNotAllowedError,
    ResolutionError,
    SecretrefError,
    VariableNotAllowedError,
)
from secretref.models.source import Source
from secretref.policies import CommandPolicy, EnvironmentPolicy, FilePolicy
from secretref.resolvers.base import Resolver
from secretref.resolvers.command import CommandResolver
from secretref.resolvers.environment import EnvironmentResolver
from secretref.resolvers.file import FileResolver
from secretref.resolvers.literal import LiteralResolver


@dataclass(frozen=True, repr=False)
class SecretRef:
    """A reference to a secret, resolved only when the value is needed.

    The point of the indirection: the config file can be committed, because
    it names the secret rather than containing it.

        {"api_key": {"env": "OPENAI_API_KEY"}}
        {"api_key": {"file": "/run/secrets/openai"}}
        {"api_key": {"command": "op read op://vault/openai/key"}}

    Resolution is lazy. A config naming twenty secrets reads none of them at
    load, so a process that uses one does not need the other nineteen to
    exist — which is what makes the same config file work in development and
    in production.
    """

    source: Source
    locator: str
    default: str | None = None
    required: bool = True

    def __repr__(self) -> str:
        """Describe this reference, never its value.

        The generated dataclass repr would print `locator`, which for a
        literal *is* the secret. A repr turns up in tracebacks, log lines,
        f-strings and pytest assertion output — none of which anyone audits
        before it is written down. So the repr is the safe description, and
        there is no way to print one of these accidentally.
        """
        parts = [f"source={self.source.value}", f"locator={self._safe_locator()}"]
        if self.default is not None:
            parts.append("default=<set>")
        if not self.required:
            parts.append("required=False")
        return f"SecretRef({', '.join(parts)})"

    def __str__(self) -> str:
        """Describe this reference, never its value."""
        return self.described()

    def _safe_locator(self) -> str:
        """Return the locator, or a notice when printing it would reveal a secret."""
        if self.source is Source.LITERAL:
            return "<redacted>"
        if self.source is Source.COMMAND:
            # Arguments can hold a secret; the executable identifies it.
            return repr(self._executable())
        return repr(self.locator)

    def resolve(self, *, allow_literal: bool = True) -> str:
        """Read the actual value.

        `allow_literal` is how a caller enforces the audit's finding: pass
        False where a literal must not be accepted, such as in production.
        """
        if self.source is Source.LITERAL and not allow_literal:
            raise ResolutionError(
                "a literal value is not allowed here. Move it out of the config "
                'and reference it instead: {"env": "YOUR_VAR"}'
            )
        cache = ResolutionCache()
        cached = cache.get(self.source.value, self.locator)
        if cached is not None:
            return cached

        value = self._read()
        if value:
            # A literal is never cached: reading it costs nothing, and
            # keeping it would hold a secret in memory for no benefit.
            if self.source is not Source.LITERAL:
                cache.put(self.source.value, self.locator, value)
            return value
        if self.default is not None:
            return self.default
        if self.required:
            raise ResolutionError(f"{self.described()} resolves to nothing")
        return ""

    def described(self) -> str:
        """Describe this reference without revealing anything.

        Safe to log, to put in an error message, and to show a user.

        A literal is described by its source alone, because any part of a
        literal is part of a secret. A command is described by its executable
        alone, because its arguments can hold one — someone will eventually
        write `curl -H "Authorization: Bearer sk-..."`, and the executable is
        enough to identify which reference failed.
        """
        if self.source is Source.LITERAL:
            return "a literal value"
        if self.source is Source.COMMAND:
            return f"command {self._executable()!r}"
        return f"{self.source.value} {self.locator!r}"

    def _executable(self) -> str:
        """Return the command's program name, without its arguments."""
        try:
            parts = shlex.split(self.locator)
        except ValueError:
            parts = self.locator.split()
        return parts[0] if parts else self.locator.strip()

    def is_resolvable(self) -> bool:
        """Whether resolving would succeed, without raising if it would not.

        For a startup check that reports every problem at once rather than
        failing on the first.

        Catches `SecretrefError` rather than only `ResolutionError`, because
        a reference a policy forbids is also one that will not resolve — and
        catching the narrower type made this raise, which in turn made the
        whole audit crash on a config it should have reported.
        """
        try:
            self.resolve()
        except SecretrefError:
            return False
        return True

    def refusal(self) -> str:
        """Why a policy would refuse this reference, or empty if it would not.

        Checks the policy without resolving. That distinction is the whole
        point: resolving a command reference *runs* it, so an audit that
        learned about refusals by attempting them would execute whatever an
        untrusted config asked for.

        Separate from `is_resolvable` because the two mean different things
        to whoever has to act. A reference that is permitted but unresolvable
        means the environment is wrong and the deployment needs fixing; one a
        policy refuses means the *config* is wrong and no deployment will.
        """
        try:
            self._check_policy()
        except (
            CommandNotAllowedError,
            FileNotAllowedError,
            VariableNotAllowedError,
        ) as error:
            return str(error)
        return ""

    def has_side_effects(self) -> bool:
        """Whether resolving this reference would do something observable.

        True only for a command reference, which starts a process. Reading a
        variable or a file does not change anything outside this process.

        What this is for: an audit of a config you did not write must not
        resolve these. Nothing else distinguishes "check whether this would
        work" from "do the thing".
        """
        return self.source is Source.COMMAND

    def _check_policy(self) -> None:
        """Ask the relevant policy whether this reference is permitted.

        Runs nothing and reads nothing. For a command reference it validates
        the parsed argument list; for the others it checks the name or path.
        """
        if self.source is Source.ENV:
            EnvironmentPolicy().check(self.locator, self.described())
        elif self.source is Source.FILE:
            FilePolicy().check_path(Path(self.locator), self.described())
        elif self.source is Source.COMMAND:
            CommandPolicy().check(self._parts(), self.described())

    def malformed(self) -> str:
        """Why this reference cannot work at all, or empty if it can.

        A config an attacker wrote need not be well formed, and neither need
        one a colleague typed in a hurry. This is checked before anything
        else, and reports without resolving — an unbalanced quote in a
        command is a config error that the audit should name as one rather
        than leave as "not verified".
        """
        if self.source is not Source.COMMAND:
            return ""
        try:
            parts = shlex.split(self.locator)
        except ValueError as error:
            return f"not a parseable command: {error}"
        return "" if parts else "an empty command"

    def _parts(self) -> list[str]:
        """Split the command, or return empty when it will not parse.

        An unparseable command yields an empty list, which the policy
        refuses. `malformed` is what distinguishes the two for a reader.
        """
        try:
            return shlex.split(self.locator)
        except ValueError:
            return []

    def as_dict(self) -> dict:
        """Round-trips with `parse`, for writing a config back out.

        A literal is written back as `[redacted]`, never as itself: this is
        the function a tool would use to rewrite a config file, and writing
        the real value would be the exact mistake the library exists to
        prevent.
        """
        if self.source is Source.LITERAL:
            return {LITERAL_KEY: REDACTED}
        data: dict = {self.source.value: self.locator}
        if self.default is not None:
            data[DEFAULT_KEY] = self.default
        if not self.required:
            data[REQUIRED_KEY] = False
        return data

    # -- reading ----------------------------------------------------------

    def _read(self) -> str:
        """Fetch the value, through the resolver for this source."""
        return _RESOLVERS[self.source].read(self.locator, self.described())

    # -- parsing ----------------------------------------------------------

    @classmethod
    def parse(cls, value: object) -> SecretRef:
        """Build a reference from whatever was in the config file.

        A mapping with one of the reference keys becomes that kind of
        reference. Anything else becomes a literal, so an existing config
        full of plain strings keeps working and the audit is what points out
        the problem.
        """
        if isinstance(value, SecretRef):
            return value
        if isinstance(value, dict):
            return cls._from_mapping(value)
        return cls(source=Source.LITERAL, locator="" if value is None else str(value))

    @classmethod
    def _from_mapping(cls, mapping: dict) -> SecretRef:
        for key, source in (
            (ENV_KEY, Source.ENV),
            (FILE_KEY, Source.FILE),
            (COMMAND_KEY, Source.COMMAND),
        ):
            if key in mapping:
                return cls(
                    source=source,
                    locator=str(mapping[key]),
                    default=cls._default_of(mapping),
                    required=bool(mapping.get(REQUIRED_KEY, True)),
                )
        if LITERAL_KEY in mapping:
            return cls(source=Source.LITERAL, locator=str(mapping[LITERAL_KEY]))
        # Built from the constants rather than written out, so a new source
        # cannot be added without this message mentioning it.
        accepted = ", ".join(f"{key!r}" for key in sorted(SECRET_KEYS))
        raise ResolutionError(
            f"a secret mapping needs one of {accepted}; got {sorted(mapping)}"
        )

    @staticmethod
    def _default_of(mapping: dict) -> str | None:
        value = mapping.get(DEFAULT_KEY)
        return None if value is None else str(value)


# Stateless, so one of each is built here and shared. Read-only, so nothing
# can register a resolver into it and change what every reference in the
# process resolves to.
_RESOLVERS: Mapping[Source, Resolver] = MappingProxyType(
    {
        Source.ENV: EnvironmentResolver(),
        Source.FILE: FileResolver(),
        Source.COMMAND: CommandResolver(),
        Source.LITERAL: LiteralResolver(),
    }
)
