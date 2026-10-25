"""One resolver per reference form.

A reference knows what it points at; a resolver knows how to fetch it.
Adding a source means a new module here and one entry in the dispatch table,
rather than another branch inside a model.

Nothing in this package imports from `models`. The dependency runs one way —
a model reaches for a resolver, never the reverse — which is what keeps the
two from importing each other.
"""

from __future__ import annotations

from secretref.resolvers.base import Resolver
from secretref.resolvers.command import CommandResolver
from secretref.resolvers.environment import EnvironmentResolver
from secretref.resolvers.file import FileResolver
from secretref.resolvers.literal import LiteralResolver

__all__ = [
    "CommandResolver",
    "EnvironmentResolver",
    "FileResolver",
    "LiteralResolver",
    "Resolver",
]
