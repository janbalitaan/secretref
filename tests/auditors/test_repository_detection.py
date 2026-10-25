"""Finding the working copy a config sits in, which decides severity."""

from __future__ import annotations

import pytest

from secretref import repository_root
from secretref.constants import MAX_PARENTS_SEARCHED


class TestRepositoryDetection:
    @pytest.mark.parametrize("marker", [".git", ".hg", ".svn"])
    def test_each_marker_is_recognized(self, tmp_path, marker):
        (tmp_path / marker).mkdir()
        assert repository_root(tmp_path) == tmp_path

    def test_a_marker_is_found_from_a_subdirectory(self, tmp_path):
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert repository_root(nested) == tmp_path

    def test_a_file_is_resolved_to_its_directory(self, tmp_path):
        (tmp_path / ".git").mkdir()
        config = tmp_path / "config.json"
        config.write_text("{}")
        assert repository_root(config) == tmp_path

    def test_a_git_file_counts_as_a_marker(self, tmp_path):
        """A worktree or submodule has a .git file rather than a directory."""
        (tmp_path / ".git").write_text("gitdir: /elsewhere")
        assert repository_root(tmp_path) == tmp_path

    def test_no_marker_returns_none(self, tmp_path):
        assert repository_root(tmp_path) is None

    def test_the_search_is_bounded(self):
        """An unusual mount can make the walk long, and the answer is not
        worth an unbounded search."""
        assert MAX_PARENTS_SEARCHED > 0
        assert MAX_PARENTS_SEARCHED < 1000
