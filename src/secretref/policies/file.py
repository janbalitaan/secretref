"""What a file reference is permitted to read.

`{"file": "/run/secrets/db-password"}` is how Kubernetes, Docker and systemd
hand a secret to a process, which makes it the most important form to support
and the second most dangerous. A config that can be written can name any path
the process can read.

Four things, each closing something measured rather than imagined:

**Allowed roots, on by default.** A reference is confined to the directories
secrets are actually mounted in, so `{"file": "/etc/shadow"}` is refused
rather than attempted.

An earlier version of this defaulted to any path, on the reasoning that a
library refusing `~/.config` would be worked around. That argues against
refusing *everything*, which is not what confining to the standard mounts
does — a container is protected with no configuration, and the unusual case
is one call. Defaulting to no protection was the weakest option defended with
an argument for a different one.

**Permission checking, off by default.** A secret file readable by group or
world is a misconfiguration whether or not anything has read it yet, and
`restrict(require_private=True)` refuses one. It is not the default because a
Kubernetes secret volume takes mode 0644 unless the pod spec says otherwise,
so requiring owner-only would refuse a standard deployment.

**Symlink resolution.** A link inside an allowed root pointing outside it
defeats the root check entirely, so the real path is what gets checked.

**A size cap.** A credential is short. Pointing a reference at a log file
should fail rather than read it into memory.

None of this makes a writable config safe. It narrows what a mistake costs.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
from threading import Lock
from typing import ClassVar

from secretref.constants import (
    GROUP_AND_WORLD_READABLE,
    SECRET_MOUNTS,
)
from secretref.exceptions import FileNotAllowedError, ResolutionError
from secretref.policies.settings import FileSettings


class FilePolicy:
    """Process-wide rules for reading a file reference.

    A singleton, like `CommandPolicy` and for the same reason: a decision
    made once at startup that every resolution has to see. A per-reference
    policy would let a reference in a config grant itself access the operator
    never allowed.

    Starts confined to `/run/secrets` and `/run/credentials` — the places
    Docker, Kubernetes and systemd actually mount secrets. A container is
    therefore protected with no configuration, and a project keeping secrets
    elsewhere says so once:

        FilePolicy().restrict(Path.home() / ".config" / "myapp")
        FilePolicy().allow_anywhere()      # or give up the protection
    """

    _instance: ClassVar[FilePolicy | None] = None
    _singleton_lock: ClassVar[Lock] = Lock()

    def __new__(cls) -> FilePolicy:
        """Return the one instance, creating it on first use."""
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._initialize()
                    cls._instance = instance
        return cls._instance

    def _initialize(self) -> None:
        """Start confined to the places secrets are mounted.

        Not "any path": a config that can be edited could otherwise name
        anything the process can read. Not "nothing" either — the file form
        exists because Docker and Kubernetes mount secrets as files, so
        refusing by default would mean the feature does not work until
        configured.

        Permission checking is a separate decision and starts off. A
        Kubernetes secret volume takes mode 0644 unless the pod spec says
        otherwise, so requiring owner-only by default would refuse a
        standard deployment.
        """
        self._settings = FileSettings()

    # -- configuration -----------------------------------------------------

    def restrict(
        self,
        *roots: Path | str,
        require_private: bool = True,
        max_bytes: int | None = None,
    ) -> None:
        """Confine file references to `roots`, and demand owner-only access.

        Naming no roots uses the places secrets are conventionally mounted,
        which is the right answer for a container and the wrong one for a
        laptop:

            FilePolicy().restrict()                     # /run/secrets, etc.
            FilePolicy().restrict("/run/secrets")       # just that one
            FilePolicy().restrict(require_private=False)  # roots only
        """
        chosen = roots or SECRET_MOUNTS
        changes: dict[str, object] = {
            "roots": tuple(Path(root).resolve() for root in chosen),
            "require_private": require_private,
        }
        if max_bytes is not None:
            changes["max_bytes"] = max_bytes
        # One assignment, so a reader never sees a half-applied policy.
        self._settings = self._settings.with_changes(**changes)

    def reset(self) -> None:
        """Return to the default: the conventional mounts, any permissions."""
        self._initialize()

    def allow_anywhere(self) -> None:
        """Permit any readable path.

        Named for what it does rather than called `relax`, because this is
        the one setting that removes the protection entirely and the call
        site should say so. For a laptop, a test, or a project that keeps
        its secrets somewhere of its own choosing.
        """
        self._settings = self._settings.with_changes(roots=(), require_private=False)

    # -- what resolution asks ----------------------------------------------

    @property
    def roots(self) -> tuple[Path, ...]:
        """Directories a reference may read from, or empty for anywhere."""
        return self._settings.roots

    @property
    def max_bytes(self) -> int:
        """Bytes a secret file may hold."""
        return self._settings.max_bytes

    def check_path(self, path: Path, described: str) -> None:
        """Refuse a path the policy does not permit, without opening it.

        For an audit, which has to report that a config names a forbidden
        path without reading what is there. Deliberately returns nothing:
        an earlier version returned the approved path, and a caller opening
        it afterwards reintroduced the race `read` exists to close.
        """
        settings = self._settings
        real = path.expanduser().resolve()
        self._check_root(real, path, described, settings)

    def read(self, path: Path, described: str) -> str:
        """Validate and read a secret file, checking the inode that is read.

        Validation and reading are deliberately one operation. A separate
        `check(path)` returning an approved path would be a footgun: the
        caller opens it afterwards, and between the two syscalls the final
        component can be replaced — so the inode that was validated would
        not be the inode that gets read.

        So the file is opened once, and the permission and size checks run
        against the open descriptor via `fstat`. `O_NOFOLLOW` on the already
        resolved path means a symlink appearing in that window is refused
        rather than followed — the resolved path's last component is not a
        link by definition, so the flag only fires if something changed.

        What this still does not defend: a *directory* above the file being
        swapped between the resolve and the open. Closing that needs an
        `openat` walk of every component, which is a great deal of machinery
        for an attacker who already has write access inside an allowed root.
        """
        settings = self._settings
        real = path.expanduser().resolve()
        self._check_root(real, path, described, settings)

        try:
            descriptor = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise FileNotAllowedError(
                    f"{described} became a symlink after it was checked, so it was not read"
                ) from error
            # Anything else — absent, unreadable — is resolution's call,
            # since whether a missing secret is an error depends on
            # `required` and `default`.
            return ""

        try:
            information = os.fstat(descriptor)
            self._check_permissions_of(information, described, settings, str(real))
            if information.st_size > settings.max_bytes:
                raise ResolutionError(
                    f"{described} holds more than {settings.max_bytes} bytes. "
                    "A credential is short; this is probably the wrong path."
                )
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                descriptor = -1  # fdopen owns it now
                return handle.read().strip()
        except UnicodeDecodeError:
            return ""
        finally:
            if descriptor != -1:
                os.close(descriptor)

    def describe(self) -> str:
        """Summarize what this policy permits, in one line. Safe to log."""
        settings = self._settings
        where = (
            ", ".join(str(root) for root in settings.roots) if settings.roots else "any path"
        )
        privacy = "owner-only" if settings.require_private else "any permissions"
        return f"file references: {where}, {privacy}, capped at {settings.max_bytes} bytes"

    # -- the checks --------------------------------------------------------

    def _check_root(
        self, real: Path, named: Path, described: str, settings: FileSettings
    ) -> None:
        """Refuse a path outside the allowed roots.

        Checked against the resolved path, because a symlink inside an
        allowed root pointing outside it would otherwise pass.
        """
        if not settings.roots:
            return
        if any(real.is_relative_to(root) for root in settings.roots):
            return
        permitted = ", ".join(str(root) for root in settings.roots)
        detail = f" (it resolves to {real})" if real != named.expanduser() else ""
        # The fix matters more than the rule. A message that states a policy
        # without naming the call that changes it turns a one-line setup into
        # a search through the source.
        raise FileNotAllowedError(
            f"{described} is outside the permitted roots{detail}.\n"
            f"  permitted: {permitted}\n"
            f"  to allow this directory:  FilePolicy().restrict({str(real.parent)!r})\n"
            "  to allow any path:        FilePolicy().allow_anywhere()\n"
            "  Only /run/secrets and /run/credentials are permitted by "
            "default, so a container is confined without configuration."
        )

    def _check_permissions_of(
        self,
        information: os.stat_result,
        described: str,
        settings: FileSettings,
        real_name: str = "the file",
    ) -> None:
        """Refuse a secret file others can read.

        Takes a stat result rather than a path, so `read` can pass the one
        from `fstat` on the open descriptor — checking the inode that will
        be read rather than whatever the name points at a moment later.
        """
        if not settings.require_private or not stat.S_ISREG(information.st_mode):
            return
        mode = stat.S_IMODE(information.st_mode)
        if mode & GROUP_AND_WORLD_READABLE:
            raise FileNotAllowedError(
                f"{described} is mode {oct(mode)}, readable beyond its owner.\n"
                f"  to fix the file:    chmod 600 {real_name}\n"
                "  to allow the mode:  FilePolicy().restrict(require_private=False)"
            )
