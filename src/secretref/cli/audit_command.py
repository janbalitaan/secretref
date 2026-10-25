"""Reporting what is wrong with a config file."""

from __future__ import annotations

from collections.abc import Sequence
import json
from pathlib import Path
import sys
from typing import TextIO

from secretref.auditors import audit
from secretref.cli.exit_codes import ExitCode
from secretref.exceptions import SecretrefError
from secretref.models.config import Config
from secretref.models.finding import Finding
from secretref.models.severity import Severity
from secretref.policies import CommandPolicy


class AuditCommand:
    """Audits a config and reports findings.

    The command this tool exists for: one line in a pipeline, and a non-zero
    exit when a config holds something it should not.
    """

    def __init__(
        self,
        path: Path | None = None,
        root: Path | None = None,
        *,
        as_json: bool = False,
        resolve: bool = False,
        strict: bool = False,
        allow_commands: Sequence[str] | None = None,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        """Set up a run.

        `strict` makes warnings blocking as well as errors, for a project
        that wants no literal secret in any config regardless of whether a
        repository was found above it.
        """
        self._path = path
        self._root = root or Path()
        self._as_json = as_json
        self._resolve = resolve
        self._strict = strict
        self._allow_commands = tuple(allow_commands or ())
        self._out = out or sys.stdout
        self._err = err or sys.stderr

    def run(self) -> ExitCode:
        """Audit, report, and return the status to exit with."""
        try:
            config = Config.load(self._path, self._root)
        except SecretrefError as error:
            print(f"error: {error}", file=self._err)
            return ExitCode.USAGE

        self._apply_policy()
        findings = audit(config, resolve=self._resolve)
        if self._as_json:
            self._report_json(config, findings)
        else:
            self._report_text(config, findings)
        return self._status(findings)

    def _apply_policy(self) -> None:
        """Set the command policy this run should audit against.

        This tool's policy is not the application's policy, and it has no way
        to learn what the application permits. Reporting a command reference
        as refused would therefore be a false error on a config that works
        perfectly in the program that owns it.

        So commands are permitted for *checking*, which runs nothing: the
        audit reports them as unverified instead. Under `--resolve` they
        would actually run, so that path demands an explicit allowlist.
        """
        if not self._resolve:
            # Permitted for checking only. The audit never resolves these.
            CommandPolicy().allow()
        elif self._allow_commands:
            CommandPolicy().allow(*self._allow_commands)
        else:
            # --resolve with nothing named: refuse rather than run anything.
            CommandPolicy().forbid()

    def _status(self, findings: list[Finding]) -> ExitCode:
        """Whether these findings should stop a build."""
        return ExitCode.FINDINGS if any(map(self._blocks, findings)) else ExitCode.OK

    def _blocks(self, finding: Finding) -> bool:
        """Whether one finding should stop a build.

        An error always does. A warning does under `--strict`, which is for
        a project that wants no literal secret in a config file whether or
        not a repository was found above it.
        """
        if finding.blocking:
            return True
        return self._strict and finding.severity is Severity.WARNING

    def _report_text(self, config: Config, findings: list[Finding]) -> None:
        """Print for a person reading a build log."""
        if not findings:
            print(f"{config.path or 'the config'}: nothing to report", file=self._out)
            return
        for finding in sorted(findings, key=lambda item: (item.severity, item.path)):
            print(finding, file=self._out)
        print(file=self._out)
        print(self._summary(findings), file=self._out)
        if not self._resolve and self._withheld(findings):
            print(
                "Command references were not run. Pass --resolve to verify them, "
                "if this config is yours.",
                file=self._out,
            )

    def _report_json(self, config: Config, findings: list[Finding]) -> None:
        """Print for a tool consuming the result."""
        worst = Severity.worst(finding.severity for finding in findings)
        print(
            json.dumps(
                {
                    "config": str(config.path) if config.path else None,
                    "resolved": self._resolve,
                    "worst": worst.value if worst else None,
                    "blocking": sum(map(self._blocks, findings)),
                    "findings": [finding.as_dict() for finding in findings],
                },
                indent=2,
            ),
            file=self._out,
        )

    @staticmethod
    def _summary(findings: list[Finding]) -> str:
        """One line counting what was found, by severity."""
        counts: dict[Severity, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        parts = [f"{counts[severity]} {severity.value}" for severity in sorted(counts)]
        return f"{len(findings)} findings: {', '.join(parts)}"

    @staticmethod
    def _withheld(findings: list[Finding]) -> bool:
        """Whether anything was reported as unverified."""
        return any("not verified" in finding.message for finding in findings)
