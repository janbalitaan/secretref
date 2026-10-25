"""Changing what the audit looks for, without waiting for a release.

The shipped rules cover eighteen published credential formats and the usual
credential key names. They cannot cover a vendor released last month, one
team's naming convention, or a version control system this version has not
heard of — and every one of those is an ordinary reason to reach into a
library like this.

Two properties carry the weight. Extending **extends** rather than replaces,
because a caller adding one key name almost never means "and stop
recognizing password". And a name that is not present raises, because
silently doing nothing would leave a caller believing a format was changed.
"""

from __future__ import annotations

import re

import pytest

from secretref import Rules
from secretref.constants import REPOSITORY_MARKERS
from secretref.exceptions import ConfigError
from secretref.patterns import KNOWN_SECRET_FORMATS, PLACEHOLDERS

FASTLY = re.compile(r"\bfsk_live_[A-Za-z0-9]{24}\b")


class TestTheDefaultsChangeNothing:
    """Adopting `Rules` has to be invisible until a caller asks otherwise."""

    def test_the_formats_are_the_shipped_ones(self):
        assert Rules.default().formats == KNOWN_SECRET_FORMATS

    def test_the_placeholders_are_the_shipped_ones(self):
        assert Rules.default().placeholders == PLACEHOLDERS

    def test_the_markers_are_the_shipped_ones(self):
        assert Rules.default().repository_markers == REPOSITORY_MARKERS

    def test_nothing_is_added_by_default(self):
        assert Rules.default().extra_key_names == frozenset()


class TestAddingAFormat:
    def test_the_format_is_appended(self):
        rules = Rules.default().with_formats({"a Fastly API token": FASTLY})
        assert rules.formats[-1] == ("a Fastly API token", FASTLY)

    def test_the_shipped_formats_are_kept(self):
        rules = Rules.default().with_formats({"a Fastly API token": FASTLY})
        assert len(rules.formats) == len(KNOWN_SECRET_FORMATS) + 1

    def test_the_original_rules_are_unchanged(self):
        """Frozen: an adjustment returns a new set rather than mutating."""
        rules = Rules.default()
        rules.with_formats({"a Fastly API token": FASTLY})
        assert len(rules.formats) == len(KNOWN_SECRET_FORMATS)


class TestReplacingAFormat:
    def test_the_replacement_is_used(self):
        name = KNOWN_SECRET_FORMATS[0][0]
        rules = Rules.default().with_formats(replace_named={name: FASTLY})
        assert dict(rules.formats)[name] is FASTLY

    def test_the_position_is_preserved(self):
        """The first match wins, so the order places narrower patterns
        before wider ones. A replacement appended would break it."""
        name = KNOWN_SECRET_FORMATS[0][0]
        rules = Rules.default().with_formats(replace_named={name: FASTLY})
        assert [n for n, _ in rules.formats] == [n for n, _ in KNOWN_SECRET_FORMATS]

    def test_the_set_is_the_same_size(self):
        name = KNOWN_SECRET_FORMATS[0][0]
        rules = Rules.default().with_formats(replace_named={name: FASTLY})
        assert len(rules.formats) == len(KNOWN_SECRET_FORMATS)


class TestRemovingAFormat:
    def test_the_format_is_gone(self):
        name = KNOWN_SECRET_FORMATS[0][0]
        rules = Rules.default().with_formats(without=(name,))
        assert name not in dict(rules.formats)

    def test_the_rest_are_kept(self):
        name = KNOWN_SECRET_FORMATS[0][0]
        rules = Rules.default().with_formats(without=(name,))
        assert len(rules.formats) == len(KNOWN_SECRET_FORMATS) - 1

    def test_all_three_compose(self):
        existing = KNOWN_SECRET_FORMATS[0][0]
        other = KNOWN_SECRET_FORMATS[1][0]
        rules = Rules.default().with_formats(
            {"a Fastly API token": FASTLY},
            replace_named={existing: FASTLY},
            without=(other,),
        )
        names = dict(rules.formats)
        assert "a Fastly API token" in names
        assert other not in names
        assert names[existing] is FASTLY


class TestAnUnknownFormatNameIsRefused:
    def test_replacing_something_absent_raises(self):
        with pytest.raises(ConfigError, match="replace_named names"):
            Rules.default().with_formats(replace_named={"a Stipe key": FASTLY})

    def test_removing_something_absent_raises(self):
        with pytest.raises(ConfigError, match="without names"):
            Rules.default().with_formats(without=("a Stipe key",))

    def test_the_message_lists_what_is_available(self):
        with pytest.raises(ConfigError) as caught:
            Rules.default().with_formats(without=("nope",))
        assert KNOWN_SECRET_FORMATS[0][0] in str(caught.value)


class TestExtendingTheKeyNames:
    def test_the_new_name_matches(self):
        rules = Rules.default().with_secret_keys(["access_pass"])
        assert rules.secret_key.search("access_pass")

    def test_the_shipped_names_still_match(self):
        """Extends rather than replaces: a caller adding one name does not
        mean "and stop recognizing password"."""
        rules = Rules.default().with_secret_keys(["access_pass"])
        for shipped in ("password", "api_key", "secret", "token"):
            assert rules.secret_key.search(shipped), shipped

    def test_matching_is_case_insensitive(self):
        rules = Rules.default().with_secret_keys(["access_pass"])
        assert rules.secret_key.search("ACCESS_PASS")

    def test_names_are_recorded(self):
        rules = Rules.default().with_secret_keys(["Access_Pass"])
        assert rules.extra_key_names == frozenset({"access_pass"})

    def test_adding_twice_accumulates(self):
        rules = Rules.default().with_secret_keys(["one"]).with_secret_keys(["two"])
        assert rules.extra_key_names == frozenset({"one", "two"})
        assert rules.secret_key.search("one")
        assert rules.secret_key.search("two")

    def test_an_empty_list_changes_nothing(self):
        rules = Rules.default()
        assert rules.with_secret_keys([]) is rules

    def test_blank_names_are_dropped(self):
        rules = Rules.default()
        assert rules.with_secret_keys(["", "   "]) is rules

    def test_a_name_with_regex_characters_is_escaped(self):
        """Taken literally, not as a pattern — otherwise a name containing a
        bracket would raise, or worse, match something unintended."""
        rules = Rules.default().with_secret_keys(["a.b[c]"])
        assert rules.secret_key.search("a.b[c]")
        assert not rules.secret_key.search("axbxcx")


class TestExtendingThePlaceholders:
    def test_a_string_pattern_is_compiled(self):
        rules = Rules.default().with_placeholders([r"^__[A-Z_]+__$"])
        assert rules.placeholders[-1].search("__REPLACE_ME__")

    def test_a_compiled_pattern_is_taken_as_given(self):
        pattern = re.compile("^x$")
        rules = Rules.default().with_placeholders([pattern])
        assert rules.placeholders[-1] is pattern

    def test_the_shipped_shapes_are_kept(self):
        rules = Rules.default().with_placeholders([r"^x$"])
        assert len(rules.placeholders) == len(PLACEHOLDERS) + 1

    def test_a_pattern_that_will_not_compile_raises_here(self):
        """Rather than at match time, when the caller has no idea which
        entry was wrong."""
        with pytest.raises(ConfigError, match="does not compile"):
            Rules.default().with_placeholders(["(unclosed"])

    def test_the_message_names_the_bad_pattern(self):
        with pytest.raises(ConfigError, match=r"\(unclosed"):
            Rules.default().with_placeholders(["(unclosed"])


class TestTheRepositoryMarkers:
    def test_markers_can_be_replaced(self):
        rules = Rules.default().with_repository_markers((".jj",))
        assert rules.repository_markers == (".jj",)

    def test_spreading_the_shipped_tuple_adds_to_it(self):
        rules = Rules.default().with_repository_markers((*REPOSITORY_MARKERS, ".jj"))
        assert ".git" in rules.repository_markers
        assert ".jj" in rules.repository_markers

    def test_an_empty_set_is_refused(self):
        """With no markers, every literal secret would be reported as being
        outside a repository — which is the quieter severity."""
        with pytest.raises(ConfigError, match="at least one repository marker"):
            Rules.default().with_repository_markers(())

    def test_blank_markers_are_dropped(self):
        with pytest.raises(ConfigError):
            Rules.default().with_repository_markers(("", None))  # type: ignore[arg-type]


class TestTheMinimumLength:
    def test_it_can_be_raised(self):
        assert Rules.default().with_minimum_length(12).min_secret_length == 12

    def test_zero_is_refused(self):
        with pytest.raises(ConfigError, match="at least 1"):
            Rules.default().with_minimum_length(0)

    def test_a_negative_length_is_refused(self):
        with pytest.raises(ConfigError):
            Rules.default().with_minimum_length(-1)


class TestDescribe:
    def test_it_counts_the_formats(self):
        assert str(len(KNOWN_SECRET_FORMATS)) in Rules.default().describe()

    def test_it_mentions_extra_key_names_when_there_are_some(self):
        described = Rules.default().with_secret_keys(["access_pass"]).describe()
        assert "extra key names" in described

    def test_it_stays_quiet_when_there_are_none(self):
        assert "extra key names" not in Rules.default().describe()

    def test_it_reveals_no_patterns(self):
        """Safe to log: a pattern can identify a vendor, and a describe that
        printed them would put the rules in every log line."""
        assert "re.compile" not in Rules.default().describe()
