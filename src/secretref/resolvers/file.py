"""Reading a secret from a mounted file."""

from __future__ import annotations

from pathlib import Path

from secretref.policies.file import FilePolicy


class FileResolver:
    """Reads a secret file, as mounted by Docker, Kubernetes or systemd.

    The policy opens and reads, rather than approving a path for this class
    to open separately. Two syscalls on a name leave a window in which the
    inode that was checked is not the inode that is read, and a path inside
    a secret mount is exactly where that matters.
    """

    def read(self, locator: str, described: str) -> str:
        """Return the file's contents, or empty when it does not exist."""
        return FilePolicy().read(Path(locator), described)
