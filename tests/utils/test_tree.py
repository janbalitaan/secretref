"""Walking a nested structure by dotted path."""

from __future__ import annotations

from collections import OrderedDict
from types import MappingProxyType

import pytest

from secretref.utils import Tree


class TestTree:
    @pytest.mark.parametrize(
        "data,path,expected",
        [
            ({"a": 1}, "a", 1),
            ({"a": {"b": 2}}, "a.b", 2),
            ({"a": [{"b": 3}]}, "a.0.b", 3),
            ({"a": ["x", "y"]}, "a.1", "y"),
        ],
    )
    def test_it_resolves_a_path(self, data, path, expected):
        assert Tree.walk(data, path) == expected

    @pytest.mark.parametrize(
        "data,path",
        [
            ({"a": 1}, "b"),
            ({"a": {"b": 1}}, "a.c"),
            ({"a": [1]}, "a.9"),
            ({"a": [1]}, "a.notanindex"),
            ({"a": 1}, "a.b"),
        ],
    )
    def test_an_unresolvable_path_is_missing(self, data, path):
        assert Tree.walk(data, path) is Tree.MISSING

    def test_stepping_into_a_scalar_is_missing(self):
        """A path cannot continue through a number."""
        assert Tree.step(42, "anything") is Tree.MISSING

    def test_stepping_into_a_string_is_missing(self):
        """A string is a Sequence, but indexing one by name means nothing."""
        assert Tree.step("hello", "0") is Tree.MISSING

    def test_the_sentinel_prints_visibly(self):
        """It shows up in a traceback, so it has to read as what it is."""
        assert repr(Tree.MISSING) == "<missing>"

    def test_the_sentinel_is_not_none(self):
        """The whole reason it exists: a stored None is a real value."""
        assert Tree.walk({"a": None}, "a") is None
        assert Tree.walk({"a": None}, "a") is not Tree.MISSING

    @pytest.mark.parametrize(
        "build",
        [
            lambda: {"a": {"b": "x"}},
            lambda: MappingProxyType({"a": {"b": "x"}}),
            lambda: OrderedDict([("a", {"b": "x"})]),
        ],
    )
    def test_any_mapping_type_works(self, build):
        """A MappingProxyType is a Mapping and not a dict; checking for `dict`
        would silently return nothing rather than fail."""
        assert Tree.walk(build(), "a.b") == "x"

    def test_join_builds_a_path(self):
        assert Tree.join("", "a") == "a"
        assert Tree.join("a", "b") == "a.b"

    def test_strings_finds_every_string(self):
        found = Tree.strings({"a": "one", "b": {"c": "two"}, "d": [3, "four"]})
        assert dict(found) == {"a": "one", "b.c": "two", "d.1": "four"}

    def test_strings_ignores_bytes(self):
        """bytes is a Sequence, and iterating one yields integers."""
        assert Tree.strings({"a": b"bytes"}) == []

    def test_mappings_with_stops_at_a_match(self):
        """A reference is a leaf: descending into it would report its own
        fields as if they were nested config."""
        found = Tree.mappings_with({"k": {"env": "X", "default": "y"}}, frozenset({"env"}))
        assert list(found) == ["k"]
        assert dict(found["k"]) == {"env": "X", "default": "y"}

    def test_mappings_with_searches_lists(self):
        found = Tree.mappings_with(
            {"p": [{"k": {"env": "A"}}, {"k": {"file": "/b"}}]},
            frozenset({"env", "file"}),
        )
        assert sorted(found) == ["p.0.k", "p.1.k"]

    def test_mappings_with_finds_nothing_in_a_scalar(self):
        assert Tree.mappings_with(42, frozenset({"env"})) == {}
