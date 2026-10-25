"""A loaded config file, with its secrets still unresolved."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar

from secretref.constants import CONFIG_NAMES, SECRET_KEYS, UNNAMED_CONFIG
from secretref.exceptions import ConfigError, ResolutionError
from secretref.models.reference import SecretRef
from secretref.parsers import parser_for
from secretref.utils.tree import Tree


class Config:
    """Parsed config, holding references rather than resolved values.

    Deliberately not a schema. A project that wants one already has pydantic
    or attrs, and this library has no business competing with either. What it
    offers instead is the part those do not: a config where secrets are
    references, and a way to reach one by path.

        config.get("timeout_seconds")                    # 30
        config.secret("providers.0.api_key").resolve()   # reads the env var

    Reading a value never resolves a secret. That separation is the point —
    nothing reads a credential as a side effect of inspecting configuration,
    including whatever prints this object.
    """

    # Searched in order when `load` is given no path and no `names`.
    #
    # A default rather than a requirement: a project that calls its config
    # something else passes `names=`, and one that does not should not have
    # to say so. The class attribute is the other lever — a subclass that
    # always looks for different filenames sets it once rather than at every
    # call site.
    NAMES: ClassVar[tuple[str, ...]] = CONFIG_NAMES

    def __init__(self, data: dict, path: Path | None = None) -> None:
        self._data = data
        self._path = path

    # -- construction -----------------------------------------------------

    @classmethod
    def load(
        cls,
        path: Path | str | None = None,
        root: Path | str = ".",
        names: Sequence[str] | None = None,
    ) -> Config:
        """Read a config file, searching for one when no path is given.

        `names` overrides which filenames are searched, for a project whose
        config is called something this library has not heard of. It defaults
        to `NAMES`, so the common case needs no argument.

        A classmethod rather than a module-level loader: a type that knows
        what it is can know how to be built, and the alternative was a module
        holding one class that nothing else in this package looks like.
        """
        candidates = tuple(names) if names else cls.NAMES
        found = Path(path) if path else cls.find(root, candidates)
        if found is None:
            raise ConfigError(
                f"no config file in {Path(root).resolve()}; looked for {', '.join(candidates)}"
            )
        return cls(parser_for(found).parse(cls._read(found), found), found)

    @classmethod
    def loads(cls, text: str, path: Path | str | None = None) -> Config:
        """Build from a string, for tests and for embedded defaults.

        `path` is optional and affects two things: which parser is chosen,
        and whether the audit can look for a repository. Without it the text
        is parsed as JSON, and a literal secret is reported as a warning
        rather than an error because there is no directory to check.
        """
        resolved = Path(path) if path else None
        return cls(parser_for(resolved).parse(text, resolved), resolved)

    @classmethod
    def find(cls, root: Path | str = ".", names: Sequence[str] | None = None) -> Path | None:
        """Find the first config filename present in `root`.

        Searched in the order given, so a caller passing `names` controls
        precedence as well as which files count.
        """
        directory = Path(root)
        candidates = tuple(names) if names else cls.NAMES
        return next(
            (directory / name for name in candidates if (directory / name).is_file()),
            None,
        )

    @staticmethod
    def _read(path: Path) -> str:
        """Read a file, naming what went wrong when it cannot be read.

        A directory with a config's name, a permission problem and a bad
        encoding all arrive as OSError, and all three are worth telling a
        caller about by filename rather than by traceback.
        """
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ConfigError(f"cannot read {path}: {error}") from error

    # -- reading ----------------------------------------------------------

    def __repr__(self) -> str:
        """Describe the config without printing any of it.

        The contents may include a literal secret — that is exactly what
        `audit()` exists to report — so a repr that dumped them would be the
        same mistake this library is written to prevent.
        """
        where = str(self._path) if self._path else "<string>"
        return f"Config(path={where!r}, keys={len(self._data)})"

    @property
    def path(self) -> Path | None:
        """Where this came from, or None when loaded from a string."""
        return self._path

    @property
    def data(self) -> Mapping[str, Any]:
        """The parsed config, as a read-only view.

        A view rather than the dict itself, so a caller cannot change the
        config after it has been audited — the findings would then describe a
        file that no longer matches what is in memory. Nested mappings are not
        copied, so this stops the common mistake rather than every one.

        One caveat: a *literal* in the config appears here as itself, because
        that is what the file contains. `audit()` is what tells you one is
        there; printing this will show it.
        """
        return MappingProxyType(self._data)

    def get(self, dotted: str, default: Any = None) -> Any:
        """Return the value at a dotted path, or `default` when absent."""
        found = Tree.walk(self._data, dotted)
        return default if found is Tree.MISSING else found

    def require(self, dotted: str) -> Any:
        """Return the value at a dotted path, raising when it is absent."""
        found = Tree.walk(self._data, dotted)
        if found is Tree.MISSING:
            raise ConfigError(f"{self._where()} has no {dotted!r}")
        return found

    def secret(self, dotted: str) -> SecretRef:
        """Return the reference at a dotted path.

        Returns the reference, not the value, so resolving stays a separate
        and visible step.
        """
        value = self.require(dotted)
        try:
            return SecretRef.parse(value)
        except ResolutionError as error:
            raise ConfigError(f"{self._where()} at {dotted!r}: {error}") from error

    def secrets(self) -> dict[str, SecretRef]:
        """Every reference in the file, keyed by its dotted path.

        What the audit walks, and what a startup check uses to report all the
        missing secrets at once rather than failing on the first.
        """
        return {
            path: SecretRef.parse(mapping)
            for path, mapping in Tree.mappings_with(self._data, SECRET_KEYS).items()
        }

    def _where(self) -> str:
        """Name this config in an error message."""
        return str(self._path) if self._path else UNNAMED_CONFIG
