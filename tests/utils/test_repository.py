"""Finding the working copy a file sits in."""

from __future__ import annotations

import pytest

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
