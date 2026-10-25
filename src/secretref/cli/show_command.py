"""Listing what a config references, without reading any of it."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import TextIO

from secretref.cli.exit_codes import ExitCode
from secretref.exceptions import SecretrefError
from secretref.models.config import Config
from secretref.models.reference import SecretRef


class ShowCommand:
    """Lists every reference in a config, by path and by source.

    Useful before a deployment: knowing which variables and files a config
    expects is more actionable than discovering them one failure at a time.

    Reads nothing. Every line comes from the config and from each reference's
    own safe description, so running this against a config you do not trust
    does nothing but parse it.
    """

    def __init__(
        self,
        path: Path | None = None,
        root: Path | None = None,
        *,
        as_json: bool = False,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        self._path = path
        self._root = root or Path()
        self._as_json = as_json
        self._out = out or sys.stdout
        self._err = err or sys.stderr

    def run(self) -> ExitCode:
        """List the references and return the status to exit with."""
        try:
            config = Config.load(self._path, self._root)
        except SecretrefError as error:
            print(f"error: {error}", file=self._err)
            return ExitCode.USAGE

        references = config.secrets()
        if self._as_json:
            self._report_json(config, references)
        else:
            self._report_text(references)
        return ExitCode.OK

    def _report_text(self, references: dict[str, SecretRef]) -> None:
        """Print for a person about to deploy."""
        if not references:
            print("no references in this config", file=self._out)
            return
        width = max(len(path) for path in references)
        for path, reference in sorted(references.items()):
            print(f"  {path:{width}}  {self._line(reference)}", file=self._out)
        print(file=self._out)
        print(f"{len(references)} references", file=self._out)

    def _report_json(self, config: Config, references: dict[str, SecretRef]) -> None:
        """Print for a tool consuming the result."""
        print(
            json.dumps(
                {
                    "config": str(config.path) if config.path else None,
                    "references": [
                        self._as_dict(path, reference)
                        for path, reference in sorted(references.items())
                    ],
                },
                indent=2,
            ),
            file=self._out,
        )

    @staticmethod
    def _line(reference: SecretRef) -> str:
        """Describe one reference, with what is optional about it."""
        notes = []
        if not reference.required:
            notes.append("optional")
        if reference.default is not None:
            notes.append("has a default")
        suffix = f"  ({', '.join(notes)})" if notes else ""
        return f"{reference.described()}{suffix}"

    @staticmethod
    def _as_dict(path: str, reference: SecretRef) -> dict[str, object]:
        """Describe one reference as data, carrying no value.

        `side_effects` is the field a tool needs: it says which references
        must not be resolved to check them.
        """
        return {
            "path": path,
            "source": reference.source.value,
            "described": reference.described(),
            "required": reference.required,
            "has_default": reference.default is not None,
            "side_effects": reference.has_side_effects(),
        }
