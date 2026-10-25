"""The command line, which is where the audit is most useful.

`audit()` in Python needs a script to wrap it. In a pipeline the useful shape
is one line that exits non-zero, so this exists to be that:

    secretref audit                    # find config.json and check it
    secretref audit path/to/config.json
    secretref audit --json             # for a tool to consume
    secretref audit --strict           # warnings block as well as errors

Exit status is the interface: 0 means nothing blocking, 1 means a blocking
finding, 2 means the command could not run at all. The last two are separate
because a pipeline needs to tell "your config has a problem" from "this tool
was used wrongly".

Commands resolve nothing with side effects unless asked. Auditing a config
from a pull request is the main use, and a command reference that resolved
would run whatever the pull request contained.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secretref.cli.audit_command import AuditCommand
from secretref.cli.exit_codes import ExitCode
from secretref.cli.policy_command import PolicyCommand
from secretref.cli.show_command import ShowCommand

__all__ = ["AuditCommand", "ExitCode", "PolicyCommand", "ShowCommand", "main"]


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser, separately so it can be tested on its own."""
    parser = argparse.ArgumentParser(
        prog="secretref",
        description="Audit config files that reference their secrets.",
        epilog=("exit status:  0 nothing blocking   1 a blocking finding   2 could not run"),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    audit = commands.add_parser(
        "audit",
        help="report secrets a config should not be holding",
        description=(
            "Reports literal secrets, references a policy forbids, and "
            "references that will not resolve. Exits 1 on anything blocking."
        ),
    )
    _add_config_arguments(audit)
    audit.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )
    audit.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as blocking, not only errors",
    )
    audit.add_argument(
        "--resolve",
        action="store_true",
        help=(
            "also check that each secret resolves. Runs command references, "
            "so only use this on a config you wrote"
        ),
    )
    audit.add_argument(
        "--allow-command",
        dest="allow_commands",
        action="append",
        metavar="NAME",
        help=(
            "an executable a command reference may run under --resolve. "
            "Repeatable. Without any, --resolve runs nothing"
        ),
    )

    show = commands.add_parser(
        "show",
        help="list what a config references, reading nothing",
        description=(
            "Lists every reference by path and source. Reads no secrets, so "
            "this is safe to run against a config you do not trust."
        ),
    )
    _add_config_arguments(show)
    show.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )

    commands.add_parser(
        "policy",
        help="print what the policies permit by default",
        description=(
            "A policy is configured in code, so this shows the defaults — "
            "which is the answer to what you get if you configure nothing."
        ),
    )
    return parser


def _add_config_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the two ways of naming a config, shared by the reading commands."""
    parser.add_argument(
        "config",
        nargs="?",
        type=Path,
        default=None,
        help="path to a config file. Searched for in --root when omitted",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(),
        help="directory to search for a config file (default: .)",
    )


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the command, and return an exit status."""
    arguments = build_parser().parse_args(argv)

    if arguments.command == "policy":
        return int(PolicyCommand().run())
    if arguments.command == "show":
        return int(
            ShowCommand(arguments.config, arguments.root, as_json=arguments.as_json).run()
        )
    return int(
        AuditCommand(
            arguments.config,
            arguments.root,
            as_json=arguments.as_json,
            resolve=arguments.resolve,
            strict=arguments.strict,
            allow_commands=arguments.allow_commands,
        ).run()
    )


def run() -> None:
    """Run as a console script, exiting rather than returning."""
    sys.exit(main())
