"""Checking a config file for secrets it should not be holding.

The failure this prevents is not a crash. A hardcoded key works perfectly —
right up until the repository is public. Nothing breaks, no test fails, and
the problem is discovered by someone else.

So the central question is not "is this value valid" but "could this value
already have been published". That is why the severity depends on whether
there is a repository above the file:

    ERROR    a literal secret inside a working copy. One commit from a
             remote, and git history keeps it after the fix.
    WARNING  a literal secret outside one. Careless, but contained.
    NOTE     a reference that currently resolves to nothing. Usually a typo
             in a variable name, occasionally a deliberately absent option.

What this is not: a repository scanner. It reads one config file and knows
nothing about history, other files, or anything already committed. For that,
gitleaks and detect-secrets answer a different question and answer it better.
"""

from __future__ import annotations

from secretref.auditors.auditor import Auditor
from secretref.auditors.placeholder import Placeholder
from secretref.auditors.secret_key import SecretKey
from secretref.models.config import Config
from secretref.models.finding import Finding
from secretref.utils.repository import Repository

__all__ = [
    "Auditor",
    "Placeholder",
    "SecretKey",
    "audit",
    "repository_root",
]


def audit(config: Config, *, resolve: bool = False) -> list[Finding]:
    """Every problem in a config file, most severe first.

    Does not resolve by default, which is a security boundary rather than a
    performance one: resolving a command reference runs it, and auditing a
    config you did not write is the main use for this. A CI check on a pull
    request would otherwise have been remote code execution.

    Pass `resolve=True` for your own config at startup, where confirming
    that a secret is actually reachable is worth more than the caution.
    """
    return Auditor(config, resolve=resolve).run()


# `repository_root` was the audit's own helper before the VCS walk was
# separated out. Kept as a name here because it is public API.
repository_root = Repository.root
