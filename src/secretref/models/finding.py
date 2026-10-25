"""Something the audit noticed about a config file."""

from __future__ import annotations

from dataclasses import dataclass

from secretref.models.severity import Severity


@dataclass(frozen=True)
class Finding:
    """One problem, located and explained.

    `path` is the dotted route to the value, so a reader can find it in the
    file. The value itself is never carried — a Finding is meant for logs and
    for CI output.
    """

    severity: Severity
    path: str
    message: str
    remedy: str = ""

    def __str__(self) -> str:
        """Format as one line, in the shape editors and CI already parse."""
        line = f"{self.severity.value}: {self.path}: {self.message}"
        return f"{line}\n  try: {self.remedy}" if self.remedy else line

    @property
    def blocking(self) -> bool:
        """Whether this should stop a deployment."""
        return self.severity is Severity.ERROR

    def as_dict(self) -> dict[str, str | bool]:
        """Convert to a plain dict, for JSON output and machine consumption.

        Carries no value, like everything else about a Finding — these are
        written to CI logs, and a tool that wrote the secret into its own
        output would undo the point.
        """
        return {
            "severity": self.severity.value,
            "path": self.path,
            "message": self.message,
            "remedy": self.remedy,
            "blocking": self.blocking,
        }
