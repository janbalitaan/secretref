"""Finding the working copy a file sits in."""

from __future__ import annotations

from pathlib import Path

import pytest

from secretref.constants import REPOSITORY_MARKERS
from secretref.exceptions import ConfigError
from secretref.utils import Repository
from secretref.utils import repository as repository_module


class TestRepository:
    @pytest.mark.parametrize("marker", [".git", ".hg", ".svn"])
    def test_each_marker_is_recognized(self, tmp_path, marker):
        (tmp_path / marker).mkdir()
        assert Repository.root(tmp_path) == tmp_path

    def test_a_marker_is_found_from_a_subdirectory(self, tmp_path):
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert Repository.root(nested) == tmp_path

    def test_a_file_resolves_to_its_directory(self, tmp_path):
        (tmp_path / ".git").mkdir()
        config = tmp_path / "config.json"
        config.write_text("{}")
        assert Repository.root(config) == tmp_path

    def test_a_git_file_counts(self, tmp_path):
        """A worktree or submodule has a .git file, not a directory."""
        (tmp_path / ".git").write_text("gitdir: /elsewhere")
        assert Repository.root(tmp_path) == tmp_path

    def test_no_marker_returns_none(self, tmp_path):
        assert Repository.root(tmp_path) is None

    def test_the_search_gives_up_rather_than_walking_forever(self, tmp_path, monkeypatch):
        """An unusual mount can make the walk long, and the answer is not
        worth an unbounded search. The cap is what this exercises."""
        monkeypatch.setattr(repository_module, "MAX_PARENTS_SEARCHED", 2)
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        assert Repository.root(deep) is None

    def test_contains_marker_is_usable_on_its_own(self, tmp_path):
        assert Repository.contains_marker(tmp_path) is False
        (tmp_path / ".git").mkdir()
        assert Repository.contains_marker(tmp_path) is True


class TestTheWalkIsAdjustable:
    """A version control system this release does not list should not mean
    waiting for the next one. The severity of a finding turns on it: a
    literal secret inside a working copy is one commit from a remote, and the
    same value outside one is careless but contained.
    """

    def test_a_custom_marker_is_found(self, tmp_path):
        (tmp_path / ".jj").mkdir()
        nested = tmp_path / "deep" / "deeper"
        nested.mkdir(parents=True)
        assert Repository.root(nested, markers=(".jj",)) == tmp_path.resolve()

    def test_the_shipped_markers_are_ignored_when_markers_are_given(self):
        """Replaces rather than extends — spreading the tuple is how a caller
        adds to it, and that distinction has to be real or the documentation
        is wrong."""
        assert Repository.root(Path(__file__), markers=(".nothing-here",)) is None

    def test_spreading_the_shipped_tuple_keeps_them(self):
        found = Repository.root(Path(__file__), markers=(*REPOSITORY_MARKERS, ".jj"))
        assert found is not None

    def test_the_walk_can_be_bounded_shorter(self):
        """A bound of 1 checks only the starting directory."""
        assert Repository.root(Path(__file__).parent, max_parents=1) is None

    def test_a_bound_of_zero_is_refused(self):
        with pytest.raises(ConfigError, match="at least 1"):
            Repository.root(Path(__file__), max_parents=0)

    def test_a_negative_bound_is_refused(self):
        with pytest.raises(ConfigError):
            Repository.root(Path(__file__), max_parents=-5)

    def test_the_walk_stops_at_the_filesystem_root(self):
        """Reaching `/` without a marker returns None rather than looping."""
        assert Repository.root(Path("/"), markers=(".nothing-here",)) is None

    def test_contains_marker_takes_markers_too(self, tmp_path):
        (tmp_path / ".jj").mkdir()
        assert Repository.contains_marker(tmp_path, markers=(".jj",))
        assert not Repository.contains_marker(tmp_path)
