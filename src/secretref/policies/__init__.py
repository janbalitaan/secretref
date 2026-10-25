"""What a reference is permitted to do, decided once at startup.

Two of the three reference forms reach outside the process, and each needs
its own answer to "may this happen at all":

    CommandPolicy       a command reference starts a process, so a writable
                        config is a config that can run code. Off by default.
    FilePolicy          a file reference reads a path, with whatever
                        permissions it has. Open by default.
    EnvironmentPolicy   an environment reference names a variable the process
                        already holds. Open by default.

The third is the least obvious and was nearly left out, on the reasoning that
reading a variable the process already has grants nothing new. That is true
and beside the point: the threat is not gaining access to the environment but
redirecting an existing data flow to carry something out of it. A field the
application displays, repointed from SUPPORT_EMAIL to AWS_SECRET_ACCESS_KEY,
leaks a key without the attacker touching the environment at all.

Two of the three start permissive. Only `CommandPolicy` is off by default,
because only it turns a writable config into code execution — the other two
raise the cost of a mistake rather than removing a capability, and a library
that rejected working configs on upgrade would get pinned to the old
version.

Both are singletons, which is the one place in this library where that is the
right answer. A policy is a decision an operator makes once and every
resolution has to see; a per-reference policy would let a reference inside a
config grant itself privileges nobody allowed, which is exactly backwards.
"""

from secretref.policies.command import CommandPolicy
from secretref.policies.environment import EnvironmentPolicy
from secretref.policies.file import FilePolicy

__all__ = ["CommandPolicy", "EnvironmentPolicy", "FilePolicy"]
