"""Reaching into nested data by dotted path."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


class Tree:
    """Navigating a structure of mappings and lists.

    Checks against the `Mapping` and `Sequence` abstractions rather than
    `dict` and `list`. The difference is not pedantic: a `MappingProxyType`,
    a `defaultdict` and an `OrderedDict` are all mappings and none of them is
    a `dict` subclass in the way these checks assumed — passing one would
    silently return nothing rather than fail, which is the worst outcome for
    a library whose job is finding things.

    Dotted paths index into lists as well as mappings, because a list of
    providers is the shape this problem actually takes: `providers.0.api_key`
    has to mean something.

    Class methods rather than instance ones: these are calculations over a
    structure the caller already holds, and wrapping it in an object would
    add a step without adding anything.
    """

    class Missing:
        """The absence of a value, distinct from a stored None.

        Needed so `get("x", default=None)` can tell "not there" from "there,
        and it is None" — a config that explicitly sets a field to null means
        something different from one that omits it.

        Nested rather than given its own file, unlike every other class here.
        It is a sentinel with one purpose, meaningless outside `Tree`, and the
        nesting is what says so: `Tree.MISSING` is the only way to refer to
        it, so nobody can compare against a second instance by accident.
        """

        def __repr__(self) -> str:
            """Render visibly in a traceback, since this is never a value."""
            return "<missing>"

    MISSING = Missing()

    @classmethod
    def walk(cls, data: Any, dotted: str) -> Any:
        """Follow a dotted path, returning MISSING when it does not resolve."""
        current: Any = data
        for part in dotted.split("."):
            current = cls.step(current, part)
            if current is cls.MISSING:
                return cls.MISSING
        return current

    @classmethod
    def step(cls, current: Any, part: str) -> Any:
        """One segment of a path, into a mapping or a list."""
        if isinstance(current, Mapping):
            return current.get(part, cls.MISSING)
        if isinstance(current, Sequence) and not isinstance(current, str | bytes):
            try:
                return current[int(part)]
            except (ValueError, IndexError):
                return cls.MISSING
        return cls.MISSING

    @staticmethod
    def join(prefix: str, part: str) -> str:
        """Append one segment to a dotted path."""
        return f"{prefix}.{part}" if prefix else part

    @classmethod
    def strings(cls, node: Any, prefix: str = "") -> list[tuple[str, str]]:
        """Every string in the tree, with its dotted path."""
        if isinstance(node, str | bytes):
            return [(prefix, node)] if isinstance(node, str) else []
        if isinstance(node, Mapping):
            return cls._strings_in_mapping(node, prefix)
        if isinstance(node, Sequence):
            return cls._strings_in_sequence(node, prefix)
        return []

    @classmethod
    def mappings_with(
        cls, node: Any, keys: frozenset[str], prefix: str = ""
    ) -> dict[str, Mapping]:
        """Every mapping in the tree holding one of `keys`, by dotted path.

        Stops descending once a mapping matches: a reference is a leaf as far
        as the caller is concerned, and walking into it would report its own
        fields as if they were nested config.
        """
        if isinstance(node, Mapping):
            return cls._mappings_in_mapping(node, keys, prefix)
        if isinstance(node, Sequence) and not isinstance(node, str | bytes):
            return cls._mappings_in_sequence(node, keys, prefix)
        return {}

    @classmethod
    def _mappings_in_mapping(
        cls, node: Mapping, keys: frozenset[str], prefix: str
    ) -> dict[str, Mapping]:
        """Collect from a mapping that either matches or holds matches."""
        if keys & set(node):
            return {prefix: node}
        found: dict[str, Mapping] = {}
        for key, value in node.items():
            found.update(cls.mappings_with(value, keys, cls.join(prefix, str(key))))
        return found

    @classmethod
    def _mappings_in_sequence(
        cls, node: Sequence, keys: frozenset[str], prefix: str
    ) -> dict[str, Mapping]:
        """Collect from a list, whose index becomes the next path segment."""
        found: dict[str, Mapping] = {}
        for index, item in enumerate(node):
            found.update(cls.mappings_with(item, keys, cls.join(prefix, str(index))))
        return found

    @classmethod
    def _strings_in_mapping(cls, node: Mapping, prefix: str) -> list[tuple[str, str]]:
        """Strings under a mapping, keyed into the path."""
        found = []
        for key, value in node.items():
            found.extend(cls.strings(value, cls.join(prefix, str(key))))
        return found

    @classmethod
    def _strings_in_sequence(cls, node: Sequence, prefix: str) -> list[tuple[str, str]]:
        """Strings under a list, indexed into the path."""
        found = []
        for index, value in enumerate(node):
            found.extend(cls.strings(value, cls.join(prefix, str(index))))
        return found
