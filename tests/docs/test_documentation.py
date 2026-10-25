"""Keeping the documentation honest.

A doc page that drifts is worse than no page: it is a claim someone will act
on. These check the things that can be checked mechanically — that every page
the index promises exists, that every link resolves, and that the API
reference names only names that are real.
"""

from __future__ import annotations

from pathlib import Path
import re

import pytest

import secretref

DOCS = Path(__file__).resolve().parents[2] / "docs"
PAGES = sorted(DOCS.glob("*.md"))


class TestEveryPageExists:
    def test_the_docs_directory_is_there(self):
        assert DOCS.is_dir()

    def test_the_index_links_only_to_pages_that_exist(self):
        """A broken link in the index is the first thing a reader hits."""
        index = (DOCS / "README.md").read_text()
        for target in re.findall(r"\]\((?!https?://)([^)#]+\.md)", index):
            assert (DOCS / target).is_file(), f"index links to a missing {target}"

    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_internal_links_resolve(self, page):
        for target in re.findall(r"\]\((?!https?://)([^)#]+\.md)", page.read_text()):
            assert (page.parent / target).is_file(), f"{page.name} links to a missing {target}"

    def test_every_page_is_reachable_from_the_index(self):
        """An unlinked page is one nobody will find."""
        index = (DOCS / "README.md").read_text()
        linked = set(re.findall(r"\]\((?!https?://)([^)#]+\.md)", index))
        for page in PAGES:
            if page.name == "README.md":
                continue
            assert page.name in linked, f"{page.name} is not linked from the index"


class TestTheApiReferenceIsReal:
    """Every name the API page documents has to exist."""

    @staticmethod
    def _documented_names() -> set[str]:
        """The names listed in the API reference's import block."""
        text = (DOCS / "api.md").read_text()
        block = re.search(r"from secretref import \((.*?)\)", text, re.S)
        assert block, "the API reference should open with an import block"
        return {name.strip().rstrip(",") for name in re.findall(r"[\w_]+,", block.group(1))}

    def test_every_documented_name_is_importable(self):
        for name in self._documented_names():
            assert hasattr(secretref, name), f"api.md documents a missing {name}"

    def test_every_public_name_is_documented(self):
        """A public name nobody wrote down is one nobody will use."""
        documented = self._documented_names()
        for name in secretref.__all__:
            assert name in documented, f"{name} is public but not in api.md"


class TestPagesSaySomething:
    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_a_page_has_a_title_and_content(self, page):
        text = page.read_text()
        assert text.startswith("# "), f"{page.name} should open with a title"
        assert len(text) > 400, f"{page.name} is too thin to be useful"
